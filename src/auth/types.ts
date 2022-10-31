export type JwtPayload = {
  userId: string;
  email: string;
};

export type JwtPayloadWithRefreshToken = JwtPayload & {
  refreshToken: string;
};
