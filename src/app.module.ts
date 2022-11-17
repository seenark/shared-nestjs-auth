import { Module, NotFoundException } from "@nestjs/common";
import { AppController } from "./app.controller";
import { AppService } from "./app.service";
import { UserController } from "./user/user.controller";
import { UserService } from "./user/user.service";
import { MulterModule } from "@nestjs/platform-express";
import { diskStorage } from "multer";
import { randomUUID } from "crypto";
import { extname, join } from "path";
import { ServeStaticModule } from "@nestjs/serve-static";
import { PrismaService } from "./prisma/prisma.service";
import { AuthController } from "./auth/auth.controller";
import { AuthService } from "./auth/auth.service";
import { JwtModule } from "@nestjs/jwt";
import { PasswordService } from "./auth/password/password.service";
import { JwtStrategy } from "./guard/jwt/jwt.service";

@Module({
  imports: [
    MulterModule.register({
      storage: diskStorage({
        destination: "./upload",
        filename(req, file, callback) {
          const ext = extname(file.originalname);
          if (ext === ".png" || ext === ".jpg") {
            const newFileName = randomUUID() + ext;
            return callback(null, newFileName);
          } else {
            return callback(
              new NotFoundException("unsupported file type"),
              null,
            );
          }
        },
      }),
    }),
    ServeStaticModule.forRoot({
      rootPath: join(__dirname, "..", "upload"),
      serveRoot: "/images", // /lo:3000/images/...png
    }),
    JwtModule.register({
      secret: "aaaa",
      signOptions: {
        expiresIn: "15m",
      },
    }),
  ],
  controllers: [AppController, UserController, AuthController],
  providers: [
    AppService,
    UserService,
    PrismaService,
    AuthService,
    PasswordService,
    JwtStrategy,
  ],
})
export class AppModule {}
