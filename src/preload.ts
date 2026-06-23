import { contextBridge, ipcRenderer } from 'electron';

contextBridge.exposeInMainWorld('electronApi', {
  readApiKey: () => ipcRenderer.invoke('read-api-key'),
  saveApiKey: (key: string) => ipcRenderer.invoke('save-api-key', key),
  createExe: (apiKey: string) =>
    ipcRenderer.invoke('create-standalone-exe', apiKey),
});
