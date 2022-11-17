import { Response } from "express";

export type TCookieOption = {
  maxAge?: number; // in milli sec
  httpOnly?: boolean;
  signed?: boolean; // indicate this cookie should be signed
  secure?: boolean; // indicate server to sent cookie while client called from https only
};
export type TCookie = (
  key: string,
  value: any,
  options?: TCookieOption,
) => void;

export type ResponseExtend = Response & TCookie;
