import {
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from "@nestjs/common";
import { User } from "@prisma/client";
import { UserService } from "src/user/user.service";
import { JwtService } from "@nestjs/jwt";
import { createHash, randomUUID } from "crypto";
import { PasswordService } from "./password/password.service";
import { IJwtPayload } from "src/guard/jwt/jwt-data.decorator";
import { getUnixTime } from "date-fns";

export interface IRefreshTokenPayload {
  jwt: string;
  userAgent: string;
  hash: string;
  iat: number;
  exp: number;
}

export interface IJwtAndRefreshPayload {
  refreshPayload: IRefreshTokenPayload;
  jwtPayload: IJwtPayload;
  user: User;
}

@Injectable()
export class AuthService {
  constructor(
    private userService: UserService,
    private jwtService: JwtService,
    private passwordService: PasswordService,
  ) {}

  async login(email: string, password: string) {
    const [error, user] = await this.validateUser(email, password);
    if (error) {
      throw error;
    }
    return user;
  }

  async validateUser(
    email: string,
    password: string,
  ): Promise<[error: Error | null, user: User | null]> {
    // get user
    const user = await this.userService.getUserByEmail(email);
    if (!user) return [new NotFoundException("not found user"), null];
    // verify password
    const isCorrected = this.passwordService.verify(password, user.password);
    if (!isCorrected) {
      return [
        new UnauthorizedException("email or password is incorrected"),
        null,
      ];
    }
    return [null, user];
  }

  generateAccessToken(email: string, name: string) {
    const payload = {
      email,
      name,
    };
    return this.jwtService.sign(payload, {
      expiresIn: "15m",
    });
  }

  decodeAccessToken(jwt: string) {
    return <IJwtPayload>this.jwtService.decode(jwt, { json: true });
  }

  private sha256(data: string) {
    return createHash("sha256").update(data).digest("hex");
  }

  generateRefreshToken(jwt: string, userAgent: string) {
    const jwtHash = this.sha256(jwt);
    const userAgentHash = this.sha256(userAgent);
    const uuid = randomUUID();
    const uuidHash = this.sha256(uuid);

    const hashForRefreshToken = this.sha256(jwtHash + userAgentHash + uuidHash);
    const payload = {
      jwt: jwt,
      userAgent: userAgent,
      hash: hashForRefreshToken,
    };
    const refreshToken = this.jwtService.sign(payload, {
      expiresIn: "30d",
      secret: "REFRESH_SECRET",
    });
    return {
      refreshToken,
      hashForRefreshToken,
      uuid,
    };
  }

  async validateRefreshToken(
    refreshJwt: string,
    userAgent: string,
  ): Promise<[boolean, IJwtAndRefreshPayload | null]> {
    const refreshPayload = <IRefreshTokenPayload>(
      this.jwtService.decode(refreshJwt)
    );
    const now = getUnixTime(new Date());
    if (refreshPayload.exp < now) {
      return [false, null];
    }
    if (refreshPayload.userAgent != userAgent) {
      return [false, null];
    }
    const jwtPayload = <IJwtPayload>this.jwtService.decode(refreshPayload.jwt);
    const user = await this.userService.getUserByEmail(jwtPayload.email);
    if (!user) {
      return [false, null];
    }
    const jwtHash = this.sha256(refreshPayload.jwt);
    const userAgentHash = this.sha256(userAgent);
    const uuidHash = this.sha256(user.uuidForRefreshToken);

    const hashForRefreshToken = this.sha256(jwtHash + userAgentHash + uuidHash);
    if (hashForRefreshToken != refreshPayload.hash) {
      return [false, null];
    }

    return [
      true,
      {
        refreshPayload,
        jwtPayload,
        user,
      },
    ];
  }
}
