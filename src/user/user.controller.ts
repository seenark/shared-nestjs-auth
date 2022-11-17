import { ZodValidationPipe } from "@anatine/zod-nestjs";
import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  InternalServerErrorException,
  NotFoundException,
  Param,
  ParseFilePipeBuilder,
  Patch,
  Post,
  Query,
  Req,
  UploadedFile,
  UseGuards,
  UseInterceptors,
  UsePipes,
} from "@nestjs/common";
import { FileInterceptor } from "@nestjs/platform-express";
import {
  ApiBody,
  ApiConsumes,
  ApiQuery,
  ApiResponse,
  ApiTags,
} from "@nestjs/swagger";
import {
  ProfileImage,
  UserDto,
  UserResponseDto,
  UserResponseSchema,
} from "./dto/user.dto";
import { UserService } from "./user.service";
import { AuthGuard } from "@nestjs/passport";
import { JwtAuthGuard } from "src/guard/jwt/jwt-auth.guard";
import { Request } from "express";
import { IJwtPayload, JwtPayload } from "src/guard/jwt/jwt-data.decorator";

@Controller("user")
@ApiTags("User")
export class UserController {
  constructor(private userService: UserService) {}

  @Get() //GET lc:3000/user
  @ApiResponse({
    type: UserDto,
    isArray: true,
  })
  @UseGuards(JwtAuthGuard)
  async getAllUser(@JwtPayload() jwtPayload: IJwtPayload) {
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
    const user = await this.userService.getUserById(+id);
    if (!user) {
      throw new NotFoundException("not found user");
    }
    return UserResponseSchema.parse(user);
  }

  @Post() // POST: /user 202 created
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
      });
      const user = UserResponseSchema.parse(savedUser);
      return user;
    } catch (error) {
      throw new InternalServerErrorException("create user error");
    }
  }

  @Patch("/:id")
  @ApiResponse({
    type: UserResponseDto,
  })
  async updateUser(@Param("id") id: string, @Body() body: UserDto) {
    console.log("patch user", body);
    try {
      const updatedUser = await this.userService.updateUser(+id, {
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

  @Delete(":id")
  @ApiResponse({
    type: UserResponseDto,
  })
  async deleteUser(@Param("id") id: string) {
    try {
      const user = await this.userService.deleteUser(+id);
      return UserResponseSchema.parse(user);
    } catch (error) {
      throw new InternalServerErrorException("delete user error");
    }
  }

  @Post("/image-profile")
  @ApiConsumes("multipart/form-data")
  @ApiBody({
    type: ProfileImage,
  })
  @UseInterceptors(FileInterceptor("image"))
  uploadImage(
    @UploadedFile(
      new ParseFilePipeBuilder()
        // .addFileTypeValidator({ fileType: "png" })
        .addMaxSizeValidator({ maxSize: 80000 })
        .build(),
    )
    file: Express.Multer.File,
  ) {
    return file;
  }
}
