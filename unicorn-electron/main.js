const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const fs = require('fs');

let mainWindow;

function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1200,
        height: 800,
        webPreferences: {
            nodeIntegration: true,
            contextIsolation: false,
            webSecurity: false  // Allows loading local files
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
        console.log('Electron app ready');
    });

    // Enable auto-refresh of progress data
    setInterval(() => {
        const progressPath = path.join(__dirname, '..', 'transfer_progress.json');
        console.log('Checking progress file at:', progressPath);
        console.log('File exists:', fs.existsSync(progressPath));
        
        if (fs.existsSync(progressPath)) {
            try {
                const progressData = fs.readFileSync(progressPath, 'utf8');
                console.log('Progress data length:', progressData.length);
                console.log('Sending update to renderer...');
                mainWindow.webContents.send('progress-update', progressData);
            } catch (error) {
                console.error('Error reading progress file:', error);
            }
        } else {
            console.log('Progress file not found');
        }
    }, 3000); // Check every 3 seconds

    // Optional: Open DevTools in development
    mainWindow.webContents.openDevTools();
}

// Handle file reading from main process (more secure)
ipcMain.handle('read-progress-file', async () => {
    try {
        const progressPath = path.join(__dirname, '..', 'transfer_progress.json');
        console.log('IPC reading from:', progressPath);
        
        if (fs.existsSync(progressPath)) {
            const data = fs.readFileSync(progressPath, 'utf8');
            console.log('IPC read data length:', data.length);
            return data;
        }
        console.log('IPC: Progress file not found, returning empty object');
        return '{}';
    } catch (error) {
        console.error('IPC Error reading progress file:', error);
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