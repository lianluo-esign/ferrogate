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
  /** True for a platform superadmin; gates the catalog platform-scope toggle (#912). */
  superadmin: boolean;
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
  /**
   * Platform-operator gateway credential minted for a superadmin login (#912
   * slice 1). Present (non-null) only for a superadmin; the console swaps to it
   * to address the PLATFORM catalog scope, never sending a tenant_id.
   */
  platform_operator_api_key: string | null;
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
