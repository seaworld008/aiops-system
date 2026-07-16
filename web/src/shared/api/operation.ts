import type { operations } from "./schema";

type AllOperationID = keyof operations;
type SuccessStatus = 200 | 201 | 202 | 204;
type ResponseMap<K extends AllOperationID> = operations[K]["responses"];
type SuccessResponse<K extends AllOperationID> = ResponseMap<K>[
  Extract<keyof ResponseMap<K>, SuccessStatus>
];
type ResponseData<T> = T extends {
  content: { "application/json": infer Data };
}
  ? Data
  : undefined;
type RequestBody<K extends AllOperationID> = operations[K] extends {
  requestBody: infer Body;
}
  ? { requestBody: Body }
  : { requestBody?: never };

export type OperationID = Exclude<AllOperationID, "getBrowserConfig">;

export type OperationInput<K extends OperationID> = {
  parameters: operations[K]["parameters"];
} & RequestBody<K>;

export type OperationResult<K extends OperationID> = {
  data: ResponseData<SuccessResponse<K>>;
  status: Extract<keyof ResponseMap<K>, SuccessStatus>;
  etag?: string;
  traceId?: string;
  location?: string;
  auditId?: string;
  idempotentReplay?: boolean;
};
