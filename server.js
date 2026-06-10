const express = require('express');
const axios = require('axios');
const cors = require('cors');
const path = require('path');
const dns = require('dns').promises;
const net = require('net');

const app = express();

// ============ CORS Configuration ============
app.use(cors({
    origin: process.env.CORS_ORIGIN || ['http://localhost:3000', 'http://localhost:5000'],
    credentials: true,
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type']
}));

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ============ Logger ============
const logger = {
    info: (msg, data = '') => console.log(`[INFO] ${new Date().toISOString()} - ${msg}`, data),
    error: (msg, error = '') => console.error(`[ERROR] ${new Date().toISOString()} - ${msg}`, error),
    warn: (msg, data = '') => console.warn(`[WARN] ${new Date().toISOString()} - ${msg}`, data)
};

// ============ Utility Functions ============

const getClientIP = (req) => {
    let ip = req.headers['x-forwarded-for'] || 
             req.headers['x-real-ip'] || 
             req.connection.remoteAddress || 
             req.socket.remoteAddress || 
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

const isValidIP = (ip) => {
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (!ipv4Regex.test(ip)) return false;
    const parts = ip.split('.');
    return parts.every(part => parseInt(part) <= 255);
};

const fetchWithRetry = async (url, options = {}, maxRetries = 2) => {
    const { timeout = 8000, headers = {} } = options;
    
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
        try {
            const response = await axios.get(url, {
                timeout,
                headers: {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) IP-Checker/2.0',
                    ...headers
                }
            });
            return response;
        } catch (error) {
            logger.warn(`Attempt ${attempt} failed:`, error.message);
            if (attempt === maxRetries) throw error;
            await new Promise(resolve => setTimeout(resolve, 1000 * attempt));
        }
    }
};

// ============ GEOLOCATION & SECURITY CHECKS ============

const getGeolocation = async (ip) => {
    try {
        const response = await fetchWithRetry(
            `http://ip-api.com/json/${ip}?fields=status,country,city,region,lat,lon,timezone,isp,org,mobile,query,proxy,hosting,vpn`,
            { timeout: 8000 }
        );

        if (response.data.status === 'fail') {
            return null;
        }

        return {
            country: response.data.country || 'Unknown',
            city: response.data.city || 'Unknown',
            region: response.data.region || 'Unknown',
            latitude: response.data.lat,
            longitude: response.data.lon,
            timezone: response.data.timezone || 'Unknown',
            isp: response.data.isp || response.data.org || 'Unknown',
            mobile: response.data.mobile || false,
            proxy: response.data.proxy || false,
            hosting: response.data.hosting || false,
            vpn: response.data.vpn || false
        };
    } catch (error) {
        logger.error('Geolocation Error:', error.message);
        return null;
    }
};

const checkVPNStatus = async (ip) => {
    try {
        const response = await fetchWithRetry(
            `http://ip-api.com/json/${ip}?fields=proxy,hosting,vpn`,
            { timeout: 8000 }
        );
        return {
            isProxy: response.data.proxy || response.data.hosting || response.data.vpn || false
        };
    } catch (error) {
        logger.error('VPN Check Error:', error.message);
        return { isProxy: false };
    }
};

const checkWikipediaBlockStatus = async (ip) => {
    try {
        const wikiUrl = `https://vi.wikipedia.org/w/api.php?action=query&list=blocks&bkip=${ip}&format=json&origin=*`;
        const response = await fetchWithRetry(wikiUrl, { timeout: 10000 });
        const blocks = response.data.query?.blocks || [];

        if (blocks.length > 0) {
            const block = blocks[0];
            return {
                isBlocked: true,
                reason: block.reason || 'Không rõ',
                expiry: block.expiry || 'Vô hạn',
                by: block.by || 'Unknown'
            };
        }

        return { isBlocked: false, reason: null, expiry: null };
    } catch (error) {
        logger.error('Wikipedia Check Error:', error.message);
        return { isBlocked: false };
    }
};

// ============ SECURITY ANALYSIS ============

const performSecurityAnalysis = async (ip, geoData) => {
    const checks = [];
    let riskScore = 0;

    // 1. VPN/Proxy Detection
    if (geoData.vpn || geoData.proxy || geoData.hosting) {
        checks.push({
            name: 'VPN/Proxy Detection',
            description: 'Kiểm tra IP có sử dụng VPN/Proxy',
            status: 'warning',
            icon: '⚠️',
            result: 'Phát hiện'
        });
        riskScore += 25;
    } else {
        checks.push({
            name: 'VPN/Proxy Detection',
            description: 'Kiểm tra IP có sử dụng VPN/Proxy',
            status: 'safe',
            icon: '✅',
            result: 'Sạch'
        });
    }

    // 2. Reverse DNS Check
    try {
        const reverseDNS = await dns.reverse(ip);
        const hostname = reverseDNS[0] || 'N/A';
        
        if (hostname.includes('proxy') || hostname.includes('vpn')) {
            checks.push({
                name: 'Reverse DNS Lookup',
                description: 'Kiểm tra hostname của IP',
                status: 'warning',
                icon: '⚠️',
                result: hostname
            });
            riskScore += 15;
        } else {
            checks.push({
                name: 'Reverse DNS Lookup',
                description: 'Kiểm tra hostname của IP',
                status: 'safe',
                icon: '✅',
                result: hostname
            });
        }
    } catch (error) {
        checks.push({
            name: 'Reverse DNS Lookup',
            description: 'Kiểm tra hostname của IP',
            status: 'safe',
            icon: '✅',
            result: 'No PTR record'
        });
    }

    // 3. Port 25 Check (SMTP - spam indicator)
    const port25Open = await checkPort(ip, 25);
    if (port25Open) {
        checks.push({
            name: 'SMTP Port (25)',
            description: 'Port SMTP - có thể liên quan spam',
            status: 'danger',
            icon: '❌',
            result: 'Mở'
        });
        riskScore += 30;
    } else {
        checks.push({
            name: 'SMTP Port (25)',
            description: 'Port SMTP - có thể liên quan spam',
            status: 'safe',
            icon: '✅',
            result: 'Đóng'
        });
    }

    // 4. ISP Reputation
    const suspiciousISPs = ['datacenter', 'cloud', 'hosting', 'server'];
    if (suspiciousISPs.some(s => geoData.isp.toLowerCase().includes(s))) {
        checks.push({
            name: 'ISP Reputation',
            description: 'Kiểm tra ISP có đáng tin cậy',
            status: 'warning',
            icon: '⚠️',
            result: geoData.isp
        });
        riskScore += 20;
    } else {
        checks.push({
            name: 'ISP Reputation',
            description: 'Kiểm tra ISP có đáng tin cậy',
            status: 'safe',
            icon: '✅',
            result: geoData.isp
        });
    }

    return {
        checks,
        score: Math.min(riskScore, 100)
    };
};

const checkPort = (ip, port) => {
    return new Promise((resolve) => {
        const socket = new net.Socket();
        socket.setTimeout(2000);
        socket.once('connect', () => {
            socket.destroy();
            resolve(true);
        });
        socket.once('timeout', () => {
            socket.destroy();
            resolve(false);
        });
        socket.once('error', () => {
            resolve(false);
        });
        socket.connect(port, ip);
    });
};

// ============ BYPASS RECOMMENDATIONS ============

const getBypassRecommendations = (data) => {
    const recommendations = [];

    if (data.isBlocked) {
        recommendations.push({
            title: 'VPN Recommendations',
            icon: '🔐',
            description: 'Sử dụng VPN uy tín để thay đổi IP',
            tips: [
                'Sử dụng Mullvad VPN (free, giấu danh)',
                'ProtonVPN (free plan có sẵn)',
                'Windscribe (500MB/tháng free)',
                'Thay đổi VPN server nếu vẫn bị khóa',
                'Chờ vài giờ rồi thử VPN khác'
            ]
        });

        recommendations.push({
            title: 'Tạo Tài Khoản Mới',
            icon: '👤',
            description: 'Tạo tài khoản Wikipedia mới để edit',
            tips: [
                'Chọn tên username độc đáo',
                'Xác minh email (nếu cần)',
                'Chờ 4-7 ngày để tài khoản autoconfirm',
                'Đăng nhập và edit bình thường',
                'Tránh edit các bài viết nhạy cảm lúc đầu'
            ]
        });

        recommendations.push({
            title: 'Appeal Process',
            icon: '📝',
            description: 'Gửi kháng cáo để xin mở khóa',
            tips: [
                'Truy cập: FAQ for blocked users',
                'Viết lý do chi tiết vì sao cần edit',
                'Gửi email tới admin Wikipedia',
                'Chờ 1-2 tuần để có phản hồi',
                'Nếu từ chối, có thể appeal lần 2'
            ]
        });
    } else {
        recommendations.push({
            title: 'Duy Trì Trạng Thái An Toàn',
            icon: '✅',
            description: 'Các cách để giữ IP sạch sẽ',
            tips: [
                'Tránh edit từ IP bị cấm trước',
                'Sử dụng tài khoản đã xác nhận',
                'Không edit liên tục từ 1 IP',
                'Tránh thay đổi nội dung quá nhanh',
                'Đọc kỹ các chính sách Wikipedia trước'
            ]
        });

        if (data.isProxy) {
            recommendations.push({
                title: 'Dùng IP Thực',
                icon: '🌐',
                description: 'Tắt VPN/Proxy nếu có thể',
                tips: [
                    'Tắt VPN trước khi edit Wikipedia',
                    'Sử dụng mạng WiFi nhà riêng',
                    'Tránh dùng shared network (cafe, trường)',
                    'Đăng nhập tài khoản để tăng độ tin cậy',
                    'Edit từ các bài viết ít nhạy cảm trước'
                ]
            });
        }

        recommendations.push({
            title: 'Best Practices',
            icon: '🎯',
            description: 'Những điều nên làm khi edit',
            tips: [
                'Tạo tài khoản + xác nhận email',
                'Đọc nguồn tham khảo trước khi edit',
                'Sử dụng edit summary chi tiết',
                'Chỉnh sửa từ từ, không spam',
                'Tham gia các discussion trước'
            ]
        });
    }

    return recommendations;
};

// ============ MAIN API ENDPOINT ============

app.get('/api/check-ip', async (req, res) => {
    const startTime = Date.now();

    try {
        let ip = getClientIP(req);
        logger.info(`IP received: ${ip}`);

        if (!isValidIP(ip)) {
            return res.status(400).json({ error: 'Invalid IP' });
        }

        // Parallel requests
        const [geoData, wikiData] = await Promise.all([
            getGeolocation(ip),
            checkWikipediaBlockStatus(ip)
        ]);

        if (!geoData) {
            return res.status(500).json({ error: 'Geolocation failed' });
        }

        // Security Analysis
        const securityAnalysis = await performSecurityAnalysis(ip, geoData);

        // Bypass Recommendations
        const bypassRecommendations = getBypassRecommendations({
            ...wikiData,
            isProxy: geoData.vpn || geoData.proxy || geoData.hosting
        });

        const response = {
            ip,
            country: geoData.country,
            city: geoData.city,
            region: geoData.region,
            latitude: geoData.latitude,
            longitude: geoData.longitude,
            timezone: geoData.timezone,
            isp: geoData.isp,
            mobile: geoData.mobile,
            
            isProxy: geoData.vpn || geoData.proxy || geoData.hosting,
            vpnStatus: (geoData.vpn || geoData.proxy || geoData.hosting) 
                ? "Phát hiện VPN/Proxy 🔒" 
                : "An toàn ✅",
            
            isBlocked: wikiData.isBlocked,
            wikipediaStatus: wikiData.isBlocked 
                ? "Bị CẤM ❌" 
                : "Sạch sẽ ✨",
            reason: wikiData.reason,
            expiry: wikiData.expiry,
            
            securityScore: securityAnalysis.score,
            securityChecks: securityAnalysis.checks,
            bypassRecommendations,
            
            timestamp: new Date().toISOString(),
            responseTime: `${Date.now() - startTime}ms`
        };

        logger.info(`Check completed for IP ${ip}`, {
            isProxy: response.isProxy,
            isBlocked: response.isBlocked,
            securityScore: response.securityScore
        });

        res.json(response);

    } catch (error) {
        logger.error('API Error:', error.message);
        res.status(500).json({
            error: 'Server error',
            message: process.env.NODE_ENV === 'development' ? error.message : 'Internal error'
        });
    }
});

app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', uptime: process.uptime() });
});

app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ============ Start Server ============

const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || 'localhost';

app.listen(PORT, HOST, () => {
    logger.info(`Server running at http://${HOST}:${PORT}`);
    logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);
});

module.exports = app;
