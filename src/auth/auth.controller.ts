import { ZodValidationPipe } from "@anatine/zod-nestjs";
import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  Res,
  UseGuards,
  UsePipes,
} from "@nestjs/common";
import { ApiResponse } from "@nestjs/swagger";
import { Request } from "express";
import { ResponseExtend } from "src/types/Response";
import { UserResponseSchema } from "src/user/dto/user.dto";
import { UserService } from "src/user/user.service";
import { AuthService, IJwtAndRefreshPayload } from "./auth.service";
import { LoginDto } from "./dto/login.dto";
import { RefreshTokenGuard } from "src/guard/refresh/refresh.strategy";
import { RefreshPayload } from "src/guard/refresh/refresh.decorator";

@Controller("auth")
@UsePipes(ZodValidationPipe)
export class AuthController {
  constructor(
    private authService: AuthService,
    private userService: UserService,
  ) {}
  @Post("login")
  @HttpCode(HttpStatus.OK)
  @ApiResponse({
    type: LoginDto,
  })
  async login(
    @Body() loginDto: LoginDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: ResponseExtend,
  ) {
    try {
      const user = await this.authService.login(
        loginDto.email,
        loginDto.password,
      );
      const jwt = this.authService.generateAccessToken(user.email, user.name);
      const userAgent = req.headers["user-agent"];
      console.log(userAgent);
      const refreshToken = this.authService.generateRefreshToken(
        jwt,
        userAgent,
      );

      const updatedUser = await this.userService.updateUser(user.id, {
        ...user,
        uuidForRefreshToken: refreshToken.uuid,
        refreshToken: refreshToken.refreshToken,
      });

      this.addCookeis(res, jwt, refreshToken.refreshToken);

      return UserResponseSchema.parse(updatedUser);
    } catch (error) {
      throw error;
    }
  }

  @Post("logout")
  @HttpCode(HttpStatus.OK)
  async logout(@Res({ passthrough: true }) res: ResponseExtend) {
    res.clearCookie("jwt");
    res.clearCookie("refresh");
  }

  @Post("refresh")
  @HttpCode(HttpStatus.OK)
  @UseGuards(RefreshTokenGuard)
  async refresh(
    @RefreshPayload() payload: IJwtAndRefreshPayload,
    @Req() req: Request,
    @Res({ passthrough: true }) res: ResponseExtend,
  ) {
    const jwt = this.authService.generateAccessToken(
      payload.jwtPayload.email,
      payload.jwtPayload.name,
    );
    const userAgent = req.headers["user-agent"];
    const refreshToken = this.authService.generateRefreshToken(jwt, userAgent);

    const updatedUser = await this.userService.updateUser(payload.user.id, {
      ...payload.user,
      uuidForRefreshToken: refreshToken.uuid,
      refreshToken: refreshToken.refreshToken,
    });

    this.addCookeis(res, jwt, refreshToken.refreshToken);
    return UserResponseSchema.parse(updatedUser);
  }

  private addCookeis(res: ResponseExtend, jwt: string, refreshToken: string) {
    res.cookie("jwt", jwt, {
      httpOnly: true,
      secure: true,
      maxAge: 1000 * 60 * 15, // milli sec
    });
    res.cookie("refresh", refreshToken, {
      httpOnly: true,
      secure: true,
      maxAge: 1000 * 60 * 60 * 24 * 30,
    });
  }
}
