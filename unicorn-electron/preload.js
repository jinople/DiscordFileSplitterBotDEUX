const { contextBridge, ipcRenderer } = require('electron');

// Expose protected methods that allow the renderer process to use
// the ipcRenderer without exposing the entire object
contextBridge.exposeInMainWorld('electronAPI', {
    readProgressFile: () => ipcRenderer.invoke('read-progress-file'),
    onProgressUpdate: (callback) => ipcRenderer.on('progress-update', callback),
    removeProgressListeners: () => ipcRenderer.removeAllListeners('progress-update')
});