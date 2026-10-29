import { mount } from "./login";

declare global {
  interface Window {
    LabHostedLogin: { mount: typeof mount };
  }
}

window.LabHostedLogin = { mount };
