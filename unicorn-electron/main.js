const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const fs = require('fs');

// Disable GPU acceleration to avoid GPU process crashes on some Windows setups
app.disableHardwareAcceleration();

let mainWindow;

function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1200,
        height: 800,
        webPreferences: {
            nodeIntegration: false,
            contextIsolation: true,
            enableRemoteModule: false,
            preload: path.join(__dirname, 'preload.js')
        },
        icon: path.join(__dirname, 'icon.png'), // Add your icon file
        title: 'Princess Unicorn Progress Tracker',
        titleBarStyle: 'default',
        show: false // Don't show until ready
    });

    // Load your HTML file
    mainWindow.loadFile('index.html');

    // Show window when ready to prevent visual flash
    mainWindow.once('ready-to-show', () => {
        mainWindow.show();
    });

    // Enable auto-refresh of progress data
    setInterval(() => {
        const progressPath = path.join(__dirname, '..', 'transfer_progress.json');
        
        if (fs.existsSync(progressPath)) {
            try {
                const progressData = fs.readFileSync(progressPath, 'utf8');
                mainWindow.webContents.send('progress-update', progressData);
            } catch (error) {
                // Silent error handling - don't log sensitive file paths
            }
        }
    }, 3000); // Check every 3 seconds

    // Optional: Open DevTools in development (disabled for security)
    // mainWindow.webContents.openDevTools();
}

// Handle file reading from main process (more secure)
ipcMain.handle('read-progress-file', async () => {
    try {
        const progressPath = path.join(__dirname, '..', 'transfer_progress.json');
        
        if (fs.existsSync(progressPath)) {
            const data = fs.readFileSync(progressPath, 'utf8');
            return data;
        }
        return '{}';
    } catch (error) {
        return '{}';
    }
});

app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') {
        app.quit();
    }
});

app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
        createWindow();
    }
});

// Auto-updater support (optional)
app.on('ready', () => {
    // You can add auto-update logic here if needed
});