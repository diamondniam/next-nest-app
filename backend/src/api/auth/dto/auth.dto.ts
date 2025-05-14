import { IsEmail, IsNotEmpty, IsStrongPassword } from 'class-validator';

export class AuthDto {
  @IsNotEmpty({ message: 'noEmail' })
  @IsEmail({}, { message: 'invalidEmail' })
  email: string;

  @IsNotEmpty({ message: 'noPassword' })
  @IsStrongPassword({}, { message: 'weakPassword' })
  password: string;

  firstName?: string;
  lastName?: string;

  rememberMe?: boolean;
}
