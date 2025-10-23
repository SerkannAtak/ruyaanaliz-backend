const express = require('express');
const axios = require('axios');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Rate limiting (basit)
const requestCounts = new Map();
const RATE_LIMIT = 10; // 10 istek per IP
const WINDOW_MS = 15 * 60 * 1000; // 15 dakika

const rateLimit = (req, res, next) => {
  const clientIP = req.ip || req.connection.remoteAddress;
  const now = Date.now();
  
  if (!requestCounts.has(clientIP)) {
    requestCounts.set(clientIP, { count: 1, resetTime: now + WINDOW_MS });
    return next();
  }
  
  const clientData = requestCounts.get(clientIP);
  
  if (now > clientData.resetTime) {
    clientData.count = 1;
    clientData.resetTime = now + WINDOW_MS;
    return next();
  }
  
  if (clientData.count >= RATE_LIMIT) {
    return res.status(429).json({ 
      error: 'Rate limit exceeded. Try again later.' 
    });
  }
  
  clientData.count++;
  next();
};

// API Key authentication
const authenticateAPI = (req, res, next) => {
  const apiKey = req.headers['x-api-key'];
  const validAPIKey = process.env.MOBILE_API_KEY || 'ruyaanaliz-mobile-2024';
  
  if (apiKey !== validAPIKey) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
};

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Dream analysis endpoint
app.post('/api/analyze-dream', rateLimit, authenticateAPI, async (req, res) => {
  try {
    const { dream, language = 'tr' } = req.body;
    
    if (!dream || dream.trim().length === 0) {
      return res.status(400).json({ error: 'Dream content is required' });
    }
    
    console.log(`Dream analysis request - Language: ${language}, Length: ${dream.length}`);
    
    // Basit dil kontrolü - mevcut prompt sistemi
    const systemPrompt = `Sen bir rüya analiz uzmanısın. Kullanıcının rüyasını analiz et ve MUTLAKA şu formatı kullan. Başka format kullanma:

[1001] Semboller: (tek kelimeler halinde, virgülle ayrılmış)
[1002] Duygusal Analiz: (rüyadaki duygular ve hisler. TEK CÜMLE CEVAP VER)
[1003] Yorum: (rüyanın genel anlamı ve mesajı)
[1004] Öneriler: (kişiye özel tavsiyeler. TEK CÜMLE CEVAP VER)
[1005] Psikolog Perspektifleri:
- Sigmund Freud: (Freud'un teorisine göre analiz. TEK CÜMLE CEVAP VER)
- Carl Gustav Jung: (Jung'un teorisine göre analiz. TEK CÜMLE CEVAP VER)
- Alfred Adler: (Adler'in teorisine göre analiz. TEK CÜMLE CEVAP VER)
- Calvin Hall: (Hall'un teorisine göre analiz. TEK CÜMLE CEVAP VER)
- Erik Erikson: (Erikson'un teorisine göre analiz. TEK CÜMLE CEVAP VER)

ÖNEMLİ: Sadece yukarıdaki formatı kullan. Başka format kullanma. KESİNLİKLE ${language} dilinde yanıt ver.`;

    // Groq API'ye istek
    const groqResponse = await axios.post('https://api.groq.com/openai/v1/chat/completions', {
      model: "llama-3.3-70b-versatile",
      messages: [
        {
          role: "system",
          content: systemPrompt
        },
        {
          role: "user",
          content: dream
        }
      ],
      max_tokens: 2000,
      temperature: 0.7
    }, {
      headers: {
        'Authorization': `Bearer ${process.env.GROQ_API_KEY}`,
        'Content-Type': 'application/json'
      },
      timeout: 30000 // 30 saniye timeout
    });
    
    const analysis = groqResponse.data.choices[0].message.content;
    
    console.log(`Analysis completed - Length: ${analysis.length}`);
    console.log(`Analysis content: ${analysis.substring(0, 200)}...`);
    
    res.json({
      success: true,
      analysis: analysis,
      timestamp: new Date().toISOString()
    });
    
  } catch (error) {
    console.error('Dream analysis error:', error.message);
    
    if (error.response) {
      console.error('Groq API error:', error.response.status, error.response.data);
      return res.status(500).json({ 
        error: 'AI analysis failed', 
        details: 'Service temporarily unavailable' 
      });
    }
    
    res.status(500).json({ 
      error: 'Internal server error',
      details: 'Please try again later'
    });
  }
});

// Error handling
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

app.listen(PORT, () => {
  console.log(`🚀 RuyaAnaliz Backend running on port ${PORT}`);
  console.log(`📊 Health check: http://localhost:${PORT}/health`);
  console.log(`🔑 API Key required for /api/analyze-dream`);
});
