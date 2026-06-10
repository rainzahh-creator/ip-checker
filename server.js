const express = require('express');
const axios = require('axios');
const cors = require('cors');
const path = require('path');

const app = express();

// ============ CORS Configuration ============
app.use(cors({
    origin: process.env.CORS_ORIGIN || ['http://localhost:3000', 'http://localhost:5000'],
    credentials: true,
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type']
}));

// ============ Middleware ============
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ============ Logger Utility ============
const logger = {
    info: (msg, data = '') => console.log(`[INFO] ${new Date().toISOString()} - ${msg}`, data),
    error: (msg, error = '') => console.error(`[ERROR] ${new Date().toISOString()} - ${msg}`, error),
    warn: (msg, data = '') => console.warn(`[WARN] ${new Date().toISOString()} - ${msg}`, data)
};

// ============ Utility Functions ============

/**
 * Lấy IP thật của client, xử lý proxy/load balancer
 */
const getClientIP = (req) => {
    let ip = req.headers['x-forwarded-for'] || 
             req.headers['x-real-ip'] || 
             req.connection.remoteAddress || 
             req.socket.remoteAddress || 
             req.connection.socket.remoteAddress ||
             '0.0.0.0';

    if (ip.includes(',')) {
        ip = ip.split(',')[0].trim();
    }

    if (ip.includes('::ffff:')) {
        ip = ip.replace('::ffff:', '');
    }

    if (ip === '::1' || ip === '127.0.0.1') {
        ip = process.env.TEST_IP || '203.162.0.1';
    }

    return ip.trim();
};

/**
 * Validate IP address (IPv4)
 */
const isValidIP = (ip) => {
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (!ipv4Regex.test(ip)) return false;
    
    const parts = ip.split('.');
    return parts.every(part => parseInt(part) <= 255);
};

/**
 * Retry logic cho API calls
 */
const fetchWithRetry = async (url, options = {}, maxRetries = 2) => {
    const { timeout = 8000, headers = {} } = options;
    
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
        try {
            const response = await axios.get(url, {
                timeout,
                headers: {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) IP-Checker/1.0',
                    ...headers
                }
            });
            return response;
        } catch (error) {
            logger.warn(`Attempt ${attempt} failed for ${url}:`, error.message);
            
            if (attempt === maxRetries) {
                throw error;
            }
            
            await new Promise(resolve => setTimeout(resolve, 1000 * attempt));
        }
    }
};

/**
 * Kiểm tra VPN/Proxy bằng IP-API
 */
const checkVPNStatus = async (ip) => {
    try {
        const response = await fetchWithRetry(
            `http://ip-api.com/json/${ip}?fields=status,message,proxy,hosting,vpn,query`,
            { timeout: 8000 }
        );

        if (response.data.status === 'fail') {
            logger.warn('IP-API returned fail status:', response.data.message);
            return { isProxy: false, details: 'Không thể xác định' };
        }

        const { proxy, hosting, vpn } = response.data;
        const isProxy = proxy || hosting || vpn || false;

        return {
            isProxy,
            details: {
                proxy: proxy || false,
                hosting: hosting || false,
                vpn: vpn || false
            }
        };
    } catch (error) {
        logger.error('VPN Check Error:', error.message);
        return { isProxy: false, details: 'Lỗi kiểm tra', error: true };
    }
};

/**
 * Kiểm tra trạng thái khóa trên Wikipedia tiếng Việt
 */
const checkWikipediaBlockStatus = async (ip) => {
    try {
        const wikiUrl = `https://vi.wikipedia.org/w/api.php?action=query&list=blocks&bkip=${ip}&format=json&origin=*`;
        
        const response = await fetchWithRetry(wikiUrl, {
            timeout: 10000,
            headers: { 'Accept': 'application/json' }
        });

        const blocks = response.data.query?.blocks || [];

        if (blocks.length > 0) {
            const block = blocks[0];
            return {
                isBlocked: true,
                reason: block.reason || 'Không rõ lý do',
                expiry: block.expiry || 'Vô hạn',
                timestamp: block.timestamp,
                by: block.by,
                blockedOnDate: new Date(block.timestamp).toLocaleString('vi-VN')
            };
        }

        return {
            isBlocked: false,
            reason: null,
            expiry: null
        };
    } catch (error) {
        logger.error('Wikipedia Block Check Error:', error.message);
        return {
            isBlocked: false,
            reason: 'Không thể kiểm tra',
            error: true
        };
    }
};

/**
 * Tạo link Wikipedia cho IP
 */
const getWikipediaLink = (ip, isBlocked) => {
    if (isBlocked) {
        return `https://vi.wikipedia.org/wiki/Special:BlockList?ip=${ip}`;
    } else {
        return `https://vi.wikipedia.org/wiki/Special:Contributions/${ip}`;
    }
};

// ============ Main API Endpoint ============
app.get('/api/check-ip', async (req, res) => {
    const startTime = Date.now();

    try {
        let ip = getClientIP(req);
        logger.info(`IP received: ${ip}`);

        if (!isValidIP(ip)) {
            logger.warn(`Invalid IP format: ${ip}`);
            return res.status(400).json({
                error: 'Địa chỉ IP không hợp lệ',
                ip: ip
            });
        }

        const vpnCheck = checkVPNStatus(ip);
        const wikiCheck = checkWikipediaBlockStatus(ip);

        const [vpnResult, wikiResult] = await Promise.all([vpnCheck, wikiCheck]);

        const wikiLink = getWikipediaLink(ip, wikiResult.isBlocked);

        const response = {
            ip: ip,
            isProxy: vpnResult.isProxy,
            vpnStatus: vpnResult.isProxy 
                ? "Phát hiện ĐANG BẬT VPN/Proxy 🔒" 
                : "An toàn (Mạng thông thường) ✅",
            vpnDetails: vpnResult.details,
            
            isBlocked: wikiResult.isBlocked,
            wikipediaStatus: wikiResult.isBlocked 
                ? "Đang bị CẤM sửa đổi! ❌" 
                : "Sạch sẽ (Không bị cấm) ✨",
            reason: wikiResult.reason || 'Không có',
            expiry: wikiResult.expiry || 'Không có',
            blockedOnDate: wikiResult.blockedOnDate || null,
            blockedBy: wikiResult.by || null,
            
            wikiLink: wikiLink,
            
            timestamp: new Date().toISOString(),
            responseTime: `${Date.now() - startTime}ms`
        };

        logger.info(`Check completed for IP ${ip}:`, {
            isProxy: vpnResult.isProxy,
            isBlocked: wikiResult.isBlocked,
            responseTime: response.responseTime
        });

        res.json(response);

    } catch (error) {
        logger.error('API Error:', error.message);
        
        res.status(500).json({
            error: 'Không thể xử lý yêu cầu kiểm tra IP',
            message: process.env.NODE_ENV === 'development' ? error.message : 'Lỗi server',
            timestamp: new Date().toISOString()
        });
    }
});

// ============ Health Check Endpoint ============
app.get('/api/health', (req, res) => {
    res.json({
        status: 'ok',
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
    });
});

// ============ 404 Handler ============
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ============ Error Handler ============
app.use((err, req, res, next) => {
    logger.error('Unhandled Error:', err.message);
    res.status(500).json({
        error: 'Internal Server Error',
        message: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong'
    });
});

// ============ Start Server ============
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || 'localhost';

app.listen(PORT, HOST, () => {
    logger.info(`Server running at http://${HOST}:${PORT}`);
    logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);
    logger.info(`CORS Origins: ${process.env.CORS_ORIGIN || 'localhost:3000, localhost:5000'}`);
});

process.on('SIGTERM', () => {
    logger.info('SIGTERM signal received: closing HTTP server');
    process.exit(0);
});

process.on('SIGINT', () => {
    logger.info('SIGINT signal received: closing HTTP server');
    process.exit(0);
});

module.exports = app;
