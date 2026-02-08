export interface User {
  Id: number;
  RoleId: number;
  Name: string;
  Email: string;
  Phone: string | null;
  Password: string;
  Address: string | null;
  Status: boolean | null;
  CreatedAt: Date | null;
}
