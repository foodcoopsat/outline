import passport from "@outlinewiki/koa-passport";
import type { Context } from "koa";
import Router from "koa-router";
import get from "lodash/get";
import { Strategy } from "passport-oauth2";
import { UserRole } from "@shared/types";
import accountProvisioner from "@server/commands/accountProvisioner";
import teamProvisioner from "@server/commands/teamProvisioner";
import userProvisioner from "@server/commands/userProvisioner";
import {
  OIDCMalformedUserInfoError,
  AuthenticationError,
} from "@server/errors";
import Logger from "@server/logging/Logger";
import passportMiddleware from "@server/middlewares/passport";
import { AuthenticationProvider, User, Team } from "@server/models";
import { AuthenticationResult } from "@server/types";
import {
  StateStore,
  getClientFromContext,
  request,
} from "@server/utils/passport";
import config from "../../plugin.json";
import env from "../env";

const router = new Router();
const scopes = env.OIDC_SCOPES.split(" ");

const authorizationParams = Strategy.prototype.authorizationParams;
Strategy.prototype.authorizationParams = function (options) {
  return {
    ...(options.originalQuery || {}),
    ...(authorizationParams.bind(this)(options) || {}),
  };
};

const authenticate = Strategy.prototype.authenticate;
Strategy.prototype.authenticate = function (req, options) {
  options.originalQuery = req.query;
  authenticate.bind(this)(req, options);
};

const base_domain = env.OIDC_BASE_DOMAIN; // "app.local.at";

Logger.debug("oidc provisioneer", `base_domain: ${base_domain}`);

async function ensureIgTeam(config_id, ip) {
  const subdomain = "ig";
  const domain = `${subdomain}.${base_domain}`;
  let igteam = await Team.findOne({
    where: { domain },
    include: [
      {
        model: AuthenticationProvider,
        as: "authenticationProviders",
        required: false,
      },
    ],
  });

  let authProvider;

  if (!igteam) {
    Logger.debug("oidc provisioneer", `creating ig team`);

    const teamParams = {
      // https://github.com/outline/outline/pull/2388#discussion_r681120224
      name: `Wiki IG`,
      domain,
      subdomain,
    };

    const authenticationProviderParams = {
      name: config_id,
      providerId: domain,
    };
    try {
      const result = await teamProvisioner({
        ...teamParams,
        authenticationProvider: authenticationProviderParams,
        ip,
      });
      Logger.debug(
        "oidc provisioneer",
        `created team with id ${result.team.id}`
      );
      igteam = result.team;
      authProvider = result.authenticationProvider;
    } catch (err) {
      Logger.error("oidc provisioneer", "Failed creating team with", err);
    }
  } else {
    // Team exists, get its authentication provider
    authProvider = await AuthenticationProvider.findOne({
      where: {
        teamId: igteam.id,
        name: config_id,
      },
    });
  }

  return { team: igteam, authenticationProvider: authProvider };
}

if (
  env.OIDC_CLIENT_ID &&
  env.OIDC_CLIENT_SECRET &&
  env.OIDC_AUTH_URI &&
  env.OIDC_TOKEN_URI &&
  env.OIDC_USERINFO_URI
) {
  passport.use(
    config.id,
    new Strategy(
      {
        authorizationURL: env.OIDC_AUTH_URI,
        tokenURL: env.OIDC_TOKEN_URI,
        clientID: env.OIDC_CLIENT_ID,
        clientSecret: env.OIDC_CLIENT_SECRET,
        callbackURL: `${env.URL}/auth/${config.id}.callback`,
        passReqToCallback: true,
        scope: env.OIDC_SCOPES,
        // @ts-expect-error custom state store
        store: new StateStore(),
        state: true,
        pkce: false,
      },
      // OpenID Connect standard profile claims can be found in the official
      // specification.
      // https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
      // Non-standard claims may be configured by individual identity providers.
      // Any claim supplied in response to the userinfo request will be
      // available on the `profile` parameter
      async function (
        ctx: Context,
        accessToken: string,
        refreshToken: string,
        params: { expires_in: number },
        _profile: unknown,
        done: (
          err: Error | null,
          user: User | null,
          result?: AuthenticationResult
        ) => void
      ) {
        try {
          // Some providers require a POST request to the userinfo endpoint, add them as exceptions here.
          const usePostMethod = [
            "https://api.dropboxapi.com/2/openid/userinfo",
          ];

          const profile = await request(
            usePostMethod.includes(env.OIDC_USERINFO_URI!) ? "POST" : "GET",
            env.OIDC_USERINFO_URI!,
            accessToken
          );
          Logger.debug("oidc provisioneer", "User profile from oidc", profile);

          if (!profile.email) {
            throw AuthenticationError(
              `An email field was not returned in the profile parameter, but is required.`
            );
          }
          if (!profile.groups || !Array.isArray(profile.groups)) {
            throw AuthenticationError(
              `Groups were not returned in the profile, but are required for foodcoops authentication.`
            );
          }

          const groups = profile.groups.filter((group) =>
            group.startsWith("fc_")
          );

          if (groups.length === 0) {
            throw AuthenticationError(
              `User does not belong to any foodcoop group (fc_*).`
            );
          }

          const client = getClientFromContext(ctx);

          // Claim name can be overriden using an env variable.
          // Default is 'preferred_username' as per OIDC spec.
          const username = get(profile, env.OIDC_USERNAME_CLAIM);
          const name = profile.name || username || profile.username;
          const profileId = profile.sub ? profile.sub : profile.id;

          if (!name) {
            throw AuthenticationError(
              `Neither a name or username was returned in the profile parameter, but at least one is required.`
            );
          }

          // Helper function to provision a team and user for a foodcoop group
          const provisionTeamAndUser = async (team_name: string) => {
            const domain = `${team_name}.${base_domain}`;
            const subdomain = team_name;

            if (!domain) {
              throw OIDCMalformedUserInfoError();
            }

            const team = await Team.findOne({ where: { domain } });

            // Only a single OIDC provider is supported – find the existing, if any.
            const authenticationProvider = team
              ? await AuthenticationProvider.findOne({
                  where: {
                    name: "oidc",
                    teamId: team.id,
                    providerId: domain,
                  },
                })
              : undefined;

            const providerId = authenticationProvider?.providerId ?? domain;

            const result = await accountProvisioner({
              ip: ctx.ip,
              team: {
                teamId: team?.id,
                // https://github.com/outline/outline/pull/2388#discussion_r681120224
                name: `Wiki ${team_name}`,
                domain,
                subdomain,
              },
              user: {
                name,
                email: profile.email,
                avatarUrl: profile.picture,
              },
              authenticationProvider: {
                name: config.id,
                providerId,
              },
              authentication: {
                providerId: profileId,
                accessToken,
                refreshToken,
                expiresIn: params.expires_in,
                scopes,
              },
            });

            Logger.debug(
              "oidc provisioneer",
              `provisioned user ${result.user.id} for team ${team_name}`
            );
            return result;
          };

          // Provision teams and users for all fc_ groups the user belongs to
          // This ensures the user can access all their foodcoop wikis
          const teamResults = await Promise.all(
            groups.map(async (group) => {
              const team_name = group.split("_", 2)[1];
              return provisionTeamAndUser(team_name);
            })
          );

          // Use the first team as the primary/default result
          let result = teamResults[0];
          Logger.debug(
            "oidc provisioneer",
            `provisioned ${teamResults.length} teams, primary team: ${result.team.domain}`
          );

          // Also ensure the user exists in the IG (inter-group) team
          const { team: igteam, authenticationProvider: igAuthProvider } =
            await ensureIgTeam(config.id, ctx.ip);

          if (!igteam || !igAuthProvider) {
            throw AuthenticationError(
              `Failed to ensure IG team and authentication provider.`
            );
          }

          let iguser = await User.findOne({
            where: { teamId: igteam.id, name },
          });
          Logger.debug("oidc provisioneer", `iguser is: ${iguser}`);

          let isNewIgUser = false;

          if (!iguser) {
            Logger.debug("oidc provisioneer", `creating new iguser`);
            const userProvisionerResult = await userProvisioner({
              name,
              email: profile.email,
              role:
                profile.groups && profile.groups.includes("Administratoren")
                  ? UserRole.Admin
                  : undefined,
              avatarUrl: profile.picture,
              teamId: igteam.id,
              ip: ctx.ip,
              authentication: {
                authenticationProviderId: igAuthProvider.id,
                providerId: profileId,
                accessToken,
                refreshToken,
                scopes,
                expiresAt: params.expires_in
                  ? new Date(Date.now() + params.expires_in * 1000)
                  : undefined,
              },
            });
            iguser = userProvisionerResult.user;
            isNewIgUser = true;

            Logger.debug(
              "oidc provisioneer",
              `created iguser with id ${iguser.id}`
            );
          }

          // Create igresult after we're sure iguser exists
          const igresult = {
            user: iguser!,
            team: igteam,
            isNewUser: isNewIgUser,
            isNewTeam: false,
          };

          // Check if a specific team was requested via state
          const state = ctx.cookies.get("state");
          Logger.debug("oidc provisioneer", `cookies state ${state}`, state);

          if (state) {
            const wanted = state.split("|")[0];
            Logger.debug("oidc provisioneer", `wanted state ${wanted}`);

            // Check if IG team was requested
            if (wanted === igteam.domain) {
              Logger.debug(
                "oidc provisioneer",
                `switch to iguser: ${iguser.id}`
              );
              result = igresult;
            } else {
              // Check if one of the foodcoop teams was requested
              const matchingResult = teamResults.find(
                (r) => r.team.domain === wanted
              );
              if (matchingResult) {
                Logger.debug(
                  "oidc provisioneer",
                  `switching to requested team: ${wanted}`
                );
                result = matchingResult;
              }
            }
          }

          Logger.debug(
            "oidc provisioneer",
            `final result team: ${result.team.domain}, user: ${result.user.id}`
          );
          return done(null, result.user, { ...result, client });
        } catch (err) {
          return done(err, null);
        }
      }
    )
  );

  router.get(config.id, passport.authenticate(config.id));
  router.get(`${config.id}.callback`, passportMiddleware(config.id));
  router.post(`${config.id}.callback`, passportMiddleware(config.id));
}

export default router;
