import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import "./index.css";
const nn = <T,>(v: T): NonNullable<T> => v as NonNullable<T>;

createRoot(nn(document.getElementById("root"))).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
