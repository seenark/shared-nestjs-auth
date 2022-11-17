import { Injectable, Logger } from "@nestjs/common";
import { PassportStrategy } from "@nestjs/passport";
import { Request } from "express";
import { Strategy, JwtFromRequestFunction, ExtractJwt } from "passport-jwt";

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, "jwt") {
  logger = new Logger(JwtStrategy.name);
  constructor() {
    const jwtExtractor: JwtFromRequestFunction = (
      req: Request,
    ): string | null => {
      try {
        const jwt = req.cookies.jwt;
        this.logger.log("jwt", jwt);
        return jwt;
      } catch (error) {
        return null;
      }
    };

    super({
      jwtFromRequest: ExtractJwt.fromExtractors([jwtExtractor]),
      ignoreExpiration: false,
      secretOrKey: "aaaa",
    });
  }

  async validate(payload: {
    email: string;
    name: string;
    iat: number;
    exp: number;
  }) {
    return payload;
  }
}
