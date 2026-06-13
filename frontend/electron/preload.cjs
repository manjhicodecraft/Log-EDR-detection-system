const { contextBridge } = require("electron");

contextBridge.exposeInMainWorld("trinetraDesktop", {
  platform: process.platform,
});
