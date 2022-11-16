import { NestFactory } from "@nestjs/core";
import { AppModule } from "./app.module";
import { DocumentBuilder, SwaggerModule } from "@nestjs/swagger";
import { NestApplicationOptions } from "@nestjs/common";
import { readFileSync } from "fs";

async function bootstrap() {
  const options: NestApplicationOptions = {
    httpsOptions: {
      key: readFileSync("./secret/cert.key"),
      cert: readFileSync("./secret/cert.crt"),
    },
  };
  const app = await NestFactory.create(AppModule, options);

  const config = new DocumentBuilder()
    .setTitle("My API")
    .setDescription("My API Description")
    .build();

  const document = SwaggerModule.createDocument(app, config);

  SwaggerModule.setup("docs", app, document);
  await app.listen(3000);
}
bootstrap();
