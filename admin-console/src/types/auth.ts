export interface AdminRegisterRequest {
  organization_name: string;
  email: string;
  password: string;
  display_name?: string;
}

export interface AdminLoginRequest {
  email: string;
  password: string;
}

export interface AdminUserView {
  id: string;
  email: string;
  display_name: string;
}

export interface AdminTenantView {
  id: string;
  name: string;
  role: string;
}

export interface AdminSessionResponse {
  access_token: string;
  refresh_token: string;
  expires_in: number;
  user: AdminUserView;
  tenant: AdminTenantView;
  gateway_api_key: string;
}

export interface AdminRefreshResponse {
  access_token: string;
  refresh_token: string;
  expires_in: number;
}

export interface AdminMeResponse {
  user: AdminUserView;
  memberships: AdminTenantView[];
}

export interface ApiErrorBody {
  error: {
    code: string;
    message: string;
  };
}

export class ApiError extends Error {
  code: string;
  status: number;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}
