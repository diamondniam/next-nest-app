import { ExceptionFilter, Catch, ArgumentsHost } from '@nestjs/common';
import { Response } from 'express';
import { HttpException } from '@nestjs/common';

@Catch(HttpException)
export class CustomExceptionFilter implements ExceptionFilter {
  catch(exception: HttpException, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();

    const status = exception.getStatus();
    const errorResponse = exception.getResponse();

    // Extract custom errorType and message from the exception response
    let errorType = errorResponse['errorType'] || undefined;
    let message = errorResponse['message'] || 'An error occurred';

    if (Array.isArray(message)) {
      errorType = message;
      message = 'Validation error';
    }

    response.status(status).json({
      errorType,
      message,
      statusCode: status,
    });
  }
}
