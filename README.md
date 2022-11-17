# What, Why, How
**What** -> Progressive backend web framework (express or fastify engine)
**Why** -> 
- typescript
- easy, 
- multiple functionalities out-of-the-box APIs
- pattern, 
- scalability
- integration (microservice, serverless), 
- openapi (swagger), 
- cronjobs
- very good documentation
- powerful command line and ease of development
- DI
- Lazy loading,
- security eg. XSS, Frame-Option, CrossDomainPolicies,StrictTransportSecurity, hidePowerBy

[Authentication Diagram](https://www.figma.com/file/hl3kZWpJMEy6cGQLo48sq6/Login-Process?node-id=0%3A1&t=oG0S8ZhgAdaHLkdH-0)

**How** 


---

# VSCode extendsion

`Prettier`


# installation

```bash
npm i -g @nestjs/cli
```

---
# New Project

```bash
nest new <project-name>
```

```bash
nest new todo
```

---
# NPM Command

```json
  "scripts": {
    "prebuild": "rimraf dist",
    "build": "nest build",
    "format": "prettier --write \"src/**/*.ts\" \"test/**/*.ts\"",
    "start": "nest start",
    "start:dev": "nest start --watch",
    "start:debug": "nest start --debug --watch",
    "start:prod": "node dist/main",
    "lint": "eslint \"{src,apps,libs,test}/**/*.ts\" --fix",
    "test": "jest",
    "test:watch": "jest --watch",
    "test:cov": "jest --coverage",
    "test:debug": "node --inspect-brk -r tsconfig-paths/register -r ts-node/register node_modules/.bin/jest --runInBand",
    "test:e2e": "jest --config ./test/jest-e2e.json"
  }
```


---

# folder structure

```bash
src
├── app.controller.spec.ts
├── app.controller.ts
├── app.module.ts
├── app.service.ts
└── main.ts
```

---
let explain...
[dev.to **sam**](https://dev.to/santypk4/bulletproof-node-js-project-architecture-4epf)

## 3 layer architecture

![[Pasted image 20221110145508.png]]

**_Don't put your business logic inside the controller_**



---

# Dive in Controller

starter contoller will be look like this
```ts
import { Controller, Get } from "@nestjs/common";
import { AppService } from "./app.service";

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get()
  getHello(): string {
    return this.appService.getHello();
  }
}
```

the controller should be register in `app.module.ts`

auto generate controller and auto register 
```bash
nest g co user --no-spec
```

## @Controller("`<name of route>`")

## @Get

- What happen if we use double @Get(), the controller willl use the first one
- @Get() with name of existing of @Get()

## @Post

## @Put

## @Patch

## @Delete

## @Body

- should not use @Body() with @Get() it seem to be OK but actually there is no spec for this thing

## @Query

## @Params

## @HttpCode
### HttpStatus

---

# Dive in Services

the business logic should be write into service 
according to the controller or can be independent job

- service is an **injectable**
- what is injectable?
- inject dependencies

service should register in `app.module.ts` as well

auto-generate and register 
```bash
nest g s user --no-spec
```


# DTO

Data transfer object
use for determining which fields should receive from frontend

---
# Entities

this is the model that represents the database table columns

![[Pasted image 20221110184000.png]]

---

# zod-nestjs & swagger

```bash
npm install openapi3-ts zod @anatine/zod-nestjs @anatine/zod-openapi
```

`tsconfig.json`
```json
"strict": true
```

on controller should use pipes
```ts
@Controller("user")
@UsePipes(ZodValidationPipe) // <-- here
export class UserController {}
```

schema

```ts
import { createZodDto } from "@anatine/zod-nestjs";
import { z } from "zod";

export const UserSchema = z.object({
  name: z.string(),
  surname: z.string(),
  age: z.number(),
});

export class UserDto extends createZodDto(UserSchema) {}
export class UserDtoArray extends createZodDto(z.array(UserSchema)) {}

```

---

# OpenAPI (Swagger)

install dependencies
```bash
npm i @nestjs/swagger @anatine/zod-openapi
```

`main.ts`

```ts
import { patchNestjsSwagger } from "@anatine/zod-nestjs";
import { DocumentBuilder, SwaggerModule } from "@nestjs/swagger";
async function bootstrap() {
  const app = await NestFactory.create(AppModule);
	// here
  const config = new DocumentBuilder()
    .setTitle("My API")
    .setDescription("My API descript")
    .setVersion("1.0")
    .addTag("1.0")
    .build();

  patchNestjsSwagger();
  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup("docs", app, document);

  await app.listen(3000, () => {
    Logger.log("Listening on :3000");
  });
}
bootstrap();
```

in controller
```ts
  @Get()
  @ApiResponse({ // <-- here
    type: UserDto,
  })
  async getAllUsers() {
    return this.userService.getAllUsers();
  }

  @Get(":id") // /user/1 | user/2
  @ApiResponse({ // <--- here
    type: UserDto,
  })
  async getUserById(@Param("id") id: string) {
    return this.userService.getUserbyId(+id);
  }

  @Post() // /user body -> name, surname
  @ApiCreatedResponse({ // <-- here
    type: UserDto,
  })
  async createUser(@Body() body: UserDto) {
    const newUser = this.userService.createUser(body);
    return newUser;
  }
```


---

# Upload file

[official docs](https://docs.nestjs.com/techniques/file-upload#file-upload)

this package is only for express engine

```bash
npm i -D @types/multer
```

set destination and filename
`app.module.ts`
```ts
@Module({
  imports: [
    MulterModule.register({
      storage: diskStorage({
        destination: "./upload",
        filename(req, file, callback) {
          const ext = extname(file.originalname);
          const name = randomUUID();
          return callback(null, `${name}${ext}`);
        },
      }),
    }),
  ],
  controllers: [AppController, UserController],
  providers: [AppService, UserService],
})
export class AppModule {}
```

then file data including new file name is appear in `file: Express.Multer.File`

```bash
file {
  fieldname: 'image',
  originalname: 'Screen Shot 2565-11-11 at 16.07.56.png',
  encoding: '7bit',
  mimetype: 'image/png',
  destination: './upload',
  filename: '3839c097-2177-4b85-b088-0950bdeac5f1.png',
  path: 'upload/3839c097-2177-4b85-b088-0950bdeac5f1.png',
  size: 754306
}
```

or want to specific by route please use **FileInterceptor()** in **@UseInterceptor()**

on the controller will do like this
```ts
@Post() // /user body -> name, surname
@ApiConsumes("multipart/form-data")
@ApiCreatedResponse({
type: UserDto,
})
@UseInterceptors(FileInterceptor("image"))
async createUser(
@Body() body: UserDto,
@UploadedFile(
  new ParseFilePipeBuilder()
	.addFileTypeValidator({ fileType: "png" })
	.addMaxSizeValidator({ maxSize: 800000 })
	.build(),
)
file: Express.Multer.File,
) {
console.log("file", file);
const newUser = this.userService.createUser(body);
return newUser;
}
```

if the system can rcvd multiple file type

```ts
@Module({
  imports: [
    MulterModule.register({
      storage: diskStorage({
        destination: "./upload",
        filename(req, file, callback) {
          const ext = extname(file.originalname);
          console.log("mimetype", file.mimetype);
          if (!file.mimetype.match(/\/(jpg|jpeg|png|gif)$/)) {
            return callback(
              new BadRequestException("unsupported file type"),
              null,
            );
          }
          const name = randomUUID();
          return callback(null, `${name}${ext}`);
        },
      }),
    }),
  ],
```

---

## delete uploaded files
we can to use normal `fs` build-in node lib
but the `fs-extra` is easier

```bash
npm i fs-extra @types/fs-extra
```

make a service
`uploaded-file.service.ts`
```ts
import { Injectable } from "@nestjs/common";
import { remove } from "fs-extra";

@Injectable()
export class UploadedFileService {
  private uploadFolder = "./upload";

  async deleteFile(name: string) {
    const fullname = `${this.uploadFolder}/${name}`;
    return remove(fullname);
  }
}

```

the delete method in controller
`user.controller.ts`
```ts
@Controller("user")
@UsePipes(ZodValidationPipe)
export class UserController {
  constructor(
    private userService: UserService,
    private uploadedFileService: UploadedFileService,
  ) {}

/*
... Res of code are not showing
*/

  @Delete()
  @ApiQuery({
    name: "name",
  })
  @ApiQuery({
    name: "ext",
    required: false,
  })
  async deleteUser(
    @Query("name") name: string,
    @Query("ext") extension: string,
  ) {
    console.log("name", name);
    return this.uploadedFileService.deleteFile(name);
  }
}

```

# Serve Static

```bash
npm i @nestjs/serve-static
```

```ts
@Module({
  imports: [
	// ...Rest of code are hidden
    ServeStaticModule.forRoot({
      rootPath: join(__dirname, "..", "upload"),
      serveRoot: "/img", // <-- don't forget slash
    }),
  ],
	// ...Rest of code are hidden
})
export class AppModule {}
```

---

# Connect to Prisma

```bash
npm i prisma @prisma/client
```

```bash
npx prisma init --datasource-provider postgresql
```

## Prisma Schema

```prisma
// This is your Prisma schema file,
// learn more about it in the docs: https://pris.ly/d/prisma-schema

generator client {
  provider = "prisma-client-js"
}

datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}

model User {
  id    String @id @default(uuid())
  email String
  name  String
}

```

## prisma service

```bash
nest g s prisma --no-spec
```

```ts
import { INestApplication, Injectable, OnModuleInit } from "@nestjs/common";
import { PrismaClient } from "@prisma/client";

@Injectable()
export class PrismaService extends PrismaClient implements OnModuleInit {
  async onModuleInit() {
    await this.$connect();
  }

  async enableShutdownHooks(app: INestApplication) {
    this.$on("beforeExit", async () => {
      await app.close();
    });
  }
}

```

---

## inject prisma service 

`user.service.ts`
```ts
@Injectable()
export class UserService {
  constructor(private prismaService: PrismaService) {}
}
```

### create user
`user.service.ts`
```ts
  async createUser(data: Prisma.UserCreateInput) {
    const user = await this.prismaService.user.create({
      data: data,
    });
    return user;
  }
```

### create user controller

`dto/user.dto.ts`
```ts
import { z } from "zod";
import { createZodDto } from "@anatine/zod-nestjs";
import { ApiProperty } from "@nestjs/swagger";

const UserSchema = z.object({
  name: z.string(),
  email: z.string(),
  password: z.string(),
});
export class UserDto extends createZodDto(UserSchema) {}

export const UserResponseSchema = z.object({
  name: z.string(),
  email: z.string(),
});

export class UserResponseDto extends createZodDto(UserResponseSchema) {}

export class ProfileImage {
  @ApiProperty({ type: "string", format: "binary" })
  image: string;

  @ApiProperty({ type: "string" })
  name: string;
}

```


`user.controller.ts`
```ts
@Controller("user")
@ApiTags("User")
export class UserController {}
```

```ts
  @Post() // POST: /user
  @HttpCode(HttpStatus.CREATED)
  @UsePipes(ZodValidationPipe)
  @ApiResponse({
    type: UserResponseDto,
  })
  async createUser(@Body() body: UserDto) {
    try {
      const savedUser = await this.userService.createUser({
        email: body.email,
        name: body.name,
        password: body.password,
        refreshToken: "",
        uuidForRefreshToken: "",
      });
      const user = UserResponseSchema.parse(savedUser);
      return user;
    } catch (error) {
      throw new InternalServerErrorException("create user error");
    }
  }
```

---

### Update User

`user.service.ts`
```ts
  async updateUser(id: string, data: Prisma.UserUpdateInput) {
    const user = await this.prismaService.user.update({
      where: {
        id,
      },
      data: data,
    });
    return user;
  }
```

`user.controller.ts`
```ts
  @Patch("/:id")
  @ApiResponse({
    type: UserResponseDto,
  })
  async updateUser(@Param("id") id: string, @Body() body: UserDto) {
    console.log("patch user", body);
    try {
      const updatedUser = await this.userService.updateUser(id, {
        email: body.email,
        name: body.name,
        password: body.password,
      });
      const user = UserResponseSchema.parse(updatedUser);
      return user;
    } catch (error) {
      throw new InternalServerErrorException("update user data error");
    }
  }
```

---

### Get user
`user.service.ts`
```ts
  async getAllUser() {
    return await this.prismaService.user.findMany();
  }

  async getUserById(id: string) {
    return await this.prismaService.user.findUnique({
      where: {
        id: id,
      },
    });
  }
```

`user.controller.ts`
```ts
  @Get() //GET lc:3000/user
  @ApiResponse({
    type: UserDto,
    isArray: true,
  })
  async getAllUser() {
    try {
      const users = await this.userService.getAllUser();
      return users.map((u) => UserResponseSchema.parse(u));
    } catch (error) {
      throw new InternalServerErrorException("error while fetching all users");
    }
  }

  @Get("/:id") // lc:3000/user/6?name=John&surname=Doe ->
  @ApiResponse({
    type: UserDto,
    isArray: true,
  })
  @ApiQuery({
    name: "name",
    required: false,
  })
  @ApiQuery({
    name: "surname",
    required: false,
  })
  async getUserById(
    @Param("id") id: string,
    @Query("name") name: string,
    @Query("surname") surname: string,
  ) {
    console.log("query params", name, surname);
    const user = await this.userService.getUserById(id);
    if (!user) {
      throw new NotFoundException("not found user");
    }
    return UserResponseSchema.parse(user);
  }
```

---
### delete

`user.service.ts`
```ts
  async deleteUser(id: string) {
    const user = await this.prismaService.user.delete({
      where: {
        id,
      },
    });
    return user;
  }
```

`user.controller.ts`
```ts
  @Delete(":id")
  @ApiResponse({
    type: UserResponseDto,
  })
  async deleteUser(@Param("id") id: string) {
    try {
      const user = await this.userService.deleteUser(id);
      return UserResponseSchema.parse(user);
    } catch (error) {
      throw new InternalServerErrorException("delete user error");
    }
  }
```



---

# Authentication

## lib
```bash
npm i @nestjs/passport passport @nestjs/jwt passport-jwt @node-rs/argon2  cookie-parser
```

```bash
npm i @types/passport-jwt @types/cookie-parser
```

register cookie-parser
`main.ts`
```ts
import { NestFactory } from "@nestjs/core";
import { AppModule } from "./app.module";
import { DocumentBuilder, SwaggerModule } from "@nestjs/swagger";
import { NestApplicationOptions } from "@nestjs/common";
import { readFileSync } from "fs";
import * as cookieParser from "cookie-parser"; // <-- here

async function bootstrap() {
  const options: NestApplicationOptions = {
    httpsOptions: {
      key: readFileSync("./secret/cert.key"),
      cert: readFileSync("./secret/cert.crt"),
    },
  };
  const app = await NestFactory.create(AppModule, options);
  app.use(cookieParser()); // <-- and here

  const config = new DocumentBuilder()
    .setTitle("My API")
    .setDescription("My API Description")
    .build();

  const document = SwaggerModule.createDocument(app, config);

  SwaggerModule.setup("docs", app, document);
  await app.listen(3000);
}
bootstrap();

```

## Model
`schema.prisma`
```prisma
model User {
  id                  Int     @id @default(autoincrement())
  email               String  @unique
  password            String
  name                String
  refreshToken        String?
  uuidForRefreshToken String?
}
```

## register jwt module
`app.module.ts`
```ts
@Module({
  imports: [
    JwtModule.register({
      secret: "aaaa",
      signOptions: {
        expiresIn: "15m",
      },
    }),
  ],
```

[argon2](https://github.com/ranisalt/node-argon2/wiki/Options)

`auth/password.service.ts`
```ts
import { Injectable } from "@nestjs/common";
import { hashSync, verifySync } from "@node-rs/argon2";

@Injectable()
export class PasswordService {
  async hashPassword(password: string) {
    const passwordHashed = hashSync(password);
    return passwordHashed;
  }

  async verify(password: string, hash: string) {
    return verifySync(hash, password);
  }
}
```


`auth.service.ts`
```ts
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
}

```

`auth/dto/login.dto.ts`
```ts
import { createZodDto } from "@anatine/zod-nestjs";
import { z } from "zod";

export const LoginSchema = z.object({
  email: z.string().email(),
  password: z.string(),
});

export class LoginDto extends createZodDto(LoginSchema) {}

```

`auth.controller.ts`
```ts
import { ZodValidationPipe } from "@anatine/zod-nestjs";
import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  Res,
  UsePipes,
} from "@nestjs/common";
import { ApiResponse } from "@nestjs/swagger";
import { Request } from "express";
import { ResponseExtend } from "src/types/Response";
import { UserResponseSchema } from "src/user/dto/user.dto";
import { UserService } from "src/user/user.service";
import { AuthService } from "./auth.service";
import { LoginDto } from "./dto/login.dto";

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
      const refreshToken = this.authService.generateRefreshToken(
        jwt,
        userAgent,
      );

      const updatedUser = await this.userService.updateUser(user.id, {
        ...user,
        uuidForRefreshToken: refreshToken.uuid,
        refreshToken: refreshToken.refreshToken,
      });

      res.cookie("jwt", jwt, {
        httpOnly: true,
        secure: true,
        maxAge: 1000 * 60 * 15,
      });
      res.cookie("refresh", refreshToken.refreshToken, {
        httpOnly: true,
        secure: true,
        maxAge: 1000 * 60 * 60 * 24 * 30,
      });
      return UserResponseSchema.parse(updatedUser);
    } catch (error) {
      throw error;
    }
  }
}

```

## Guard

```bash
nest g s guard/jwt
```

`jwt.service.ts`
```ts
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
        const jwt = req.cookies["jwt"];
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
    return {
      email: payload.email,
      name: payload.name,
    };
  }
}

```

register `JwtStrategy` class to app.module.ts
`app.module.ts`
```ts
  providers: [
    AppService,
    UserService,
    PrismaService,
    AuthService,
    PasswordService,
    JwtStrategy, // <-- here
  ],
```


use `JwtStrategy`
```ts
import { AuthGuard } from "@nestjs/passport";

  @Get() //GET lc:3000/user
  @ApiResponse({
    type: UserDto,
    isArray: true,
  })
  @UseGuards(AuthGuard("jwt")) // <-- here
  async getAllUser() {
    try {
      const users = await this.userService.getAllUser();
      return users.map((u) => UserResponseSchema.parse(u));
    } catch (error) {
      throw new InternalServerErrorException("error while fetching all users");
    }
  }
```


use JwtAuthGuard 
`auth/guard/jwt-auth.guard.ts`
```ts
import { AuthGuard } from "@nestjs/passport";
export class JwtAuthGuard extends AuthGuard("jwt") {}

```


Pull data from jwt payload

```ts
  @UseGuards(JwtAuthGuard)
  async getAllUser(@Req() req: Request) {
    console.log("user data from jwt", <any>req.user);
  }
```

easy way to get Data from JWT Payload

make a custom decorator
`guard/jwt/jwt-data.decorator.ts`
```ts
import { createParamDecorator, ExecutionContext } from "@nestjs/common";

export interface IJwtPayload {
  email: string;
  name: string;
}

export const JwtPayload = createParamDecorator(
  (data: unknown, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    return <IJwtPayload>request.user;
  },
);

```

use JwtPayload decorator

controller
```ts
  @Get() //GET lc:3000/user
  @ApiResponse({
    type: UserDto,
    isArray: true,
  })
  @UseGuards(JwtAuthGuard)
  async getAllUser(@JwtPayload() jwtPayload: IJwtPayload) { // <-- here
    try {
      const users = await this.userService.getAllUser();
      return users.map((u) => UserResponseSchema.parse(u));
    } catch (error) {
      throw new InternalServerErrorException("error while fetching all users");
    }
  }
```

## Logout

`auth.controller.ts`
```ts
  @Post("logout")
  @HttpCode(HttpStatus.OK)
  async logout(@Res({ passthrough: true }) res: ResponseExtend) {
    res.clearCookie("jwt");
    res.clearCookie("refresh");
  }
```

---

## Refresh token guard

`auth.service.ts`
```ts
async validateRefreshToken(
    refreshJwt: string,
    userAgent: string,
  ): Promise<
    [
      boolean,
      { refreshPayload: IRefreshTokenPayload; jwtPayload: IJwtPayload } | null,
    ]
  > {
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
      },
    ];
  }
```

`guard/refresh/refresh.strategy.ts`
```ts
import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
} from "@nestjs/common";
import { Request } from "express";
import { AuthService } from "src/auth/auth.service";

@Injectable()
export class RefreshTokenGuard implements CanActivate {
  constructor(private authService: AuthService) {}
  async canActivate(context: ExecutionContext) {
    const req: Request = context.switchToHttp().getRequest();
    const refreshJwt = req.cookies.refresh;
    if (!refreshJwt) {
      throw new UnauthorizedException("not found refresh token");
    }
    const userAgent = req.headers["user-agent"];

    const [valid, refreshPayload] = await this.authService.validateRefreshToken(
      refreshJwt,
      userAgent,
    );

    if (!valid) {
      throw new UnauthorizedException("invalid refresh token");
    }
    (req as any).payload = refreshPayload;

    return true;
  }
}

```

`auth.controller.ts`
```ts
  @Post("refresh")
  @HttpCode(HttpStatus.OK)
  @UseGuards(RefreshTokenGuard)
  async refresh(
    @Req() req: Request,
    @Res({ passthrough: true }) res: ResponseExtend,
  ) {
    console.log("req", (req as any).payload); // <-- the payload inject to request
    return "Ok";
  }
```

get payload easy way
`guard/refresh/refresh.decorator.ts`
```ts
import { createParamDecorator, ExecutionContext } from "@nestjs/common";
import { IJwtAndRefreshPayload } from "src/auth/auth.service";

export const RefreshPayload = createParamDecorator(
  (data: unknown, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    return <IJwtAndRefreshPayload>request.payload;
  },
);

```

use it like this
```ts
 @Post("refresh")
  @HttpCode(HttpStatus.OK)
  @UseGuards(RefreshTokenGuard)
  async refresh(
    @RefreshPayload() payload: IJwtAndRefreshPayload,
    @Res({ passthrough: true }) res: ResponseExtend,
  ) {
    console.log("payload", payload);
    return "Ok";
  }
```


---

## Create new access token and new refresh token

create a common function to attach jwt and refreshtoken to cookies
`auth.controller.ts`
```ts
  private addCookeis(res: ResponseExtend, jwt: string, refreshToken: string) {
    res.cookie("jwt", jwt, {
      httpOnly: true,
      secure: true,
      maxAge: 1000 * 60 * 15,
    });
    res.cookie("refresh", refreshToken, {
      httpOnly: true,
      secure: true,
      maxAge: 1000 * 60 * 60 * 24 * 30,
    });
  }
```


## @Post refresh
`auth.controller.ts`
```ts
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
```

