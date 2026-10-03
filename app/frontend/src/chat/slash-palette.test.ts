import { describe, expect, it } from "vitest";
import { commandAtStart } from "./slash-palette";

describe("slash-palette commandAtStart", () => {
  it("detecta / solo al inicio (con o sin filtro)", () => {
    expect(commandAtStart("/")).toBe("");
    expect(commandAtStart("/who")).toBe("who");
    expect(commandAtStart("/WHOAMI")).toBe("whoami");
    expect(commandAtStart("  /help")).toBe("help");
  });

  it("rechaza texto normal y comandos con args", () => {
    expect(commandAtStart("")).toBeNull();
    expect(commandAtStart("hola")).toBeNull();
    expect(commandAtStart("dime /whoami")).toBeNull();
    expect(commandAtStart("/foo bar")).toBeNull();
    expect(commandAtStart("/whoami ")).toBeNull();
  });
});
