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
  });
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
      Logger.debug("oidc provisioneer", "created team", result);
      igteam = result.team;
    } catch (err) {
      Logger.error("oidc provisioneer", "Failed creating team with", err);
    }
    Logger.debug("oidc provisioneer", `created ig team`, igteam);
  }
  return igteam;
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
          const groups = profile.groups.filter((group) =>
            group.startsWith("fc_")
          );
          const team_name = groups[0].split("_", 2)[1];
          const client = getClientFromContext(ctx);
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

          let result = await accountProvisioner({
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

          Logger.debug("oidc provisioneer", `user with ${result}`, result);

          const igteam = await ensureIgTeam(config.id, ctx.ip);

          let iguser = await User.findOne({
            where: { teamId: igteam.id, name },
          });
          Logger.debug("oidc provisioneer", `iguser is: ${iguser}`);

          const igresult = {
            user: iguser,
            team: igteam,
            isNewUser: false,
            isNewTeam: false,
          };
          if (!iguser) {
            Logger.debug("oidc provisioneer", `creating new iguser`);
            const userParams = {
              name,
              email: profile.email,
              avatarUrl: profile.picture,
            };
            iguser = await userProvisioner({
              name: userParams.name,
              email: userParams.email,
              language: userParams.language,
              role: profile.groups.includes("Administratoren")
                ? UserRole.Admin
                : undefined,
              avatarUrl: userParams.avatarUrl,
              teamId: igteam.id,
              ip: ctx.ip,
              authentication: {
                authenticationProviderId: authenticationProvider.id,
                providerId: profileId,
                accessToken,
                refreshToken,
                scopes,
                expiresAt: params.expiresIn
                  ? new Date(Date.now() + params.expiresIn * 1000)
                  : undefined,
              },
            });
            igresult.isNewUser = true;
            igresult.user = result.user;

            Logger.debug(
              "oidc provisioneer",
              `created iguser with ${igresult}`,
              igresult
            );
          }
          const state = ctx.cookies.get("state");
          Logger.debug("oidc provisioneer", `cookies state ${state}`, state);
          const wanted = state.split("|")[0];
          Logger.debug("oidc provisioneer", `wanted state ${wanted}`);
          if (wanted === igteam.domain) {
            Logger.debug(
              "oidc provisioneer",
              `switch to iguser: ${iguser}`,
              iguser
            );
            result = igresult;
          }
          Logger.debug("oidc provisioneer", `result is: ${result}`, result);
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
