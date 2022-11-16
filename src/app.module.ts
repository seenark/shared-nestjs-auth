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
import { PrismaService } from './prisma/prisma.service';

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
  ],
  controllers: [AppController, UserController],
  providers: [AppService, UserService, PrismaService],
})
export class AppModule {}
