// nav 项
export interface NavOptionT<T = string> {
  id: string;
  label: T;
  path: T;
  children?: NavOptionT[];
}

// tab 项
export interface TabOptionT<LabelT = string, ValueT = string> {
  label: LabelT;
  value: ValueT;
}
