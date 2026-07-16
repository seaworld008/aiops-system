import {
  type ColumnDef,
  flexRender,
  getCoreRowModel,
  useReactTable,
} from "@tanstack/react-table";
import {
  type Key,
  type ReactNode,
  useMemo,
} from "react";

export type DataTableColumn<Row> = {
  id: string;
  header: ReactNode;
  cell: (row: Row) => ReactNode;
};

type DataTableProps<Row> = {
  ariaLabel: string;
  columns: readonly DataTableColumn<Row>[];
  rows: readonly Row[];
  rowKey: (row: Row) => Key;
};

export function DataTable<Row>({
  ariaLabel,
  columns,
  rows,
  rowKey,
}: DataTableProps<Row>) {
  const tableColumns = useMemo<ColumnDef<Row>[]>(
    () =>
      columns.map((column) => ({
        id: column.id,
        header: () => column.header,
        cell: (context) => column.cell(context.row.original),
      })),
    [columns],
  );
  const table = useReactTable({
    data: [...rows],
    columns: tableColumns,
    getRowId: (row) => String(rowKey(row)),
    getCoreRowModel: getCoreRowModel(),
  });

  return (
    <div className="data-table-scroll">
      <table aria-label={ariaLabel} className="data-table">
        <thead>
          {table.getHeaderGroups().map((group) => (
            <tr key={group.id}>
              {group.headers.map((header) => (
                <th key={header.id} scope="col">
                  {header.isPlaceholder
                    ? null
                    : flexRender(
                        header.column.columnDef.header,
                        header.getContext(),
                      )}
                </th>
              ))}
            </tr>
          ))}
        </thead>
        <tbody>
          {table.getRowModel().rows.map((row) => (
            <tr key={row.id}>
              {row.getVisibleCells().map((cell) => (
                <td key={cell.id}>
                  {flexRender(cell.column.columnDef.cell, cell.getContext())}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
