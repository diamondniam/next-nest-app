import {
  HttpException,
  HttpStatus,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { PrismaService } from 'src/prisma/prisma.service';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { Request, Response } from 'express';

const accessTokenCookieName = 'accessToken';
const refreshTokenCookieName = 'refreshToken';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService,
  ) {}

  async signin({ dto, res }: { dto: AuthDto; res: Response }) {
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });

    if (!user) {
      throw new HttpException(
        {
          message: 'Error logging in',
        },
        HttpStatus.FORBIDDEN,
      );
    }

    const pwMatches = await argon.verify(user.password, dto.password);

    if (!pwMatches) {
      throw new HttpException(
        {
          message: 'Error logging in',
        },
        HttpStatus.FORBIDDEN,
      );
    }

    await this.signToken({
      userId: user.id,
      email: user.email,
      rememberMe: dto.rememberMe || false,
      response: res,
    });

    delete (user as any).password;

    return {
      user,
    };
  }

  async signup({ dto, res }: { dto: AuthDto; res: Response }) {
    const hash = await argon.hash(dto.password);

    try {
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          password: hash,
          firstName: dto.firstName,
          lastName: dto.lastName,
        },
      });

      const token = await this.signToken({
        userId: user.id,
        email: user.email,
        rememberMe: dto.rememberMe || false,
        response: res,
      });

      delete (user as any).password;

      return {
        user,
      };
    } catch (error) {
      if (error.code === 'P2002') {
        throw new HttpException(
          {
            message: 'Email already taken',
            errorType: 'emailTaken',
          },
          HttpStatus.CONFLICT,
        );
      }
      throw error;
    }
  }

  logout({ res }: { res: Response }) {
    res.clearCookie(accessTokenCookieName, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      path: '/',
    });

    res.clearCookie(refreshTokenCookieName, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      path: '/',
    });

    return {
      message: 'Successfully logged out',
    };
  }

  async refresh({ res, req }: { res: Response; req: Request }) {
    const refreshToken = req.cookies?.refreshToken;

    if (!refreshToken) {
      throw new UnauthorizedException();
    }

    try {
      const payload = await this.jwt.verifyAsync(refreshToken, {
        secret: this.config.get('JWT_REFRESH_SECRET'),
      });

      const user = await this.prisma.user.findUnique({
        where: {
          id: payload.sub,
        },
      });

      if (!user) {
        throw new UnauthorizedException();
      }

      await this.signToken({
        userId: user.id,
        email: user.email,
        rememberMe: false,
        response: res,
      });

      return {
        user,
      };
    } catch (error) {
      throw new UnauthorizedException();
    }
  }

  async signToken({
    userId,
    email,
    rememberMe,
    response,
  }: {
    userId: number;
    email: string;
    rememberMe: boolean;
    response: Response;
  }) {
    const secret = this.config.get('JWT_SECRET');
    const refreshSecret = this.config.get('JWT_REFRESH_SECRET');

    const payload = {
      sub: userId,
      email,
    };

    const token = await this.jwt.signAsync(payload, {
      expiresIn: '15m',
      secret: secret,
    });
    let refreshToken = '';

    response.cookie(accessTokenCookieName, token, {
      httpOnly: true,
      sameSite: 'strict',
      secure: true,
      maxAge: 1000 * 60 * 15,
      path: '/',
    });

    if (rememberMe) {
      refreshToken = await this.jwt.signAsync(payload, {
        expiresIn: '7d',
        secret: refreshSecret,
      });

      response.cookie(refreshTokenCookieName, refreshToken, {
        httpOnly: true,
        sameSite: 'strict',
        secure: true,
        maxAge: 1000 * 60 * 60 * 24 * 7,
        path: '/',
      });
    }

    // return {
    //   accessToken: token,
    //   refreshToken: rememberMe ? refreshToken : null,
    // };
  }
}
