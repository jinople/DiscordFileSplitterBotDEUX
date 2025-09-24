const express = require('express');
const chokidar = require('chokidar');
const WebSocket = require('ws');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = 8000;

// Serve static files
app.use(express.static('.'));

// WebSocket server for hot reload
const wss = new WebSocket.Server({ port: 8001 });

// Track connected clients
const clients = new Set();

wss.on('connection', (ws) => {
    clients.add(ws);
    console.log('Princess connected for progress updates!');
    
    ws.on('close', () => {
        clients.delete(ws);
        console.log('Client disconnected');
    });
});

// Watch the transfer_progress.json file directly in this folder
const progressFile = './transfer_progress.json';

const watcher = chokidar.watch(progressFile, {
    ignoreInitial: true
});

watcher.on('change', (filePath) => {
    console.log('Transfer progress updated!');
    
    // Notify all connected clients to reload
    clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
            client.send(JSON.stringify({ 
                type: 'reload', 
                file: 'transfer_progress.json',
                message: 'New chunks uploaded! Refreshing princess view!'
            }));
        }
    });
});

// Also watch HTML/CSS/JS files for changes
chokidar.watch('.', {
    ignored: ['node_modules', 'transfer_progress.json', 'uploads', 'cogs', '__pycache__', 'venv', '*.py', '*.bat', '*.sh'], 
    ignoreInitial: true
}).on('change', (filePath) => {
    if (filePath.match(/\.(html|css|js)$/)) {
        console.log('Interface file changed:', filePath);
        
        clients.forEach(client => {
            if (client.readyState === WebSocket.OPEN) {
                client.send(JSON.stringify({ 
                    type: 'reload', 
                    file: filePath,
                    message: 'Princess says: Interface updated!'
                }));
            }
        });
    }
});

// Inject hot reload script into HTML files
app.use((req, res, next) => {
    if (req.path.endsWith('.html')) {
        const filePath = path.join(__dirname, req.path);
        
        if (fs.existsSync(filePath)) {
            let html = fs.readFileSync(filePath, 'utf8');
            
            // Inject hot reload script
            const hotReloadScript = `
                <script>
                    const ws = new WebSocket('ws://localhost:8001');
                    ws.onmessage = (event) => {
                        const data = JSON.parse(event.data);
                        if (data.type === 'reload') {
                            console.log(data.message);
                            setTimeout(() => location.reload(), 500);
                        }
                    };
                    ws.onopen = () => console.log('Princess Hot Reload Connected!');
                    ws.onclose = () => console.log('Hot reload disconnected');
                </script>
            `;
            
            html = html.replace('</body>', hotReloadScript + '</body>');
            res.send(html);
            return;
        }
    }
    next();
});

// Default route
app.get('/', (req, res) => {
    res.redirect('/index.html');
});

app.listen(PORT, () => {
    console.log(`
PRINCESS UNICORN SERVER
    
    Progress Tracker: http://localhost:${PORT}
    Hot reload: Enabled!
    Watching: transfer_progress.json
    Auto-updates when chunks complete!
    
    Ready to track your magical uploads!
    `);
});

process.on('SIGINT', () => {
    console.log('\nShutting down Princess Server...');
    watcher.close();
    wss.close();
    process.exit(0);
});