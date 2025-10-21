const express = require('express');
const axios = require('axios');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 8080;

app.use(cors());
app.use(express.json());

app.get('/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

app.post('/api/analyze-dream', async (req, res) => {
  try {
    const { dream, language = 'tr' } = req.body;
    
    const response = await axios.post('https://api.groq.com/openai/v1/chat/completions', {
      model: "llama-3.3-70b-versatile",
      messages: [
        {
          role: "system",
          content: `Sen bir rüya analiz uzmanısın. Kullanıcının rüyasını analiz et ve MUTLAKA şu formatı kullan. Başka format kullanma:

[1001] Semboller: (tek kelimeler halinde, virgülle ayrılmış)
[1002] Duygusal Analiz: (rüyadaki duygular ve hisler)
[1003] Yorum: (rüyanın genel anlamı ve mesajı)
[1004] Öneriler: (kişiye özel tavsiyeler)
[1005] Psikolog Perspektifleri:
- Sigmund Freud: (Freud'un teorisine göre analiz)
- Carl Gustav Jung: (Jung'un teorisine göre analiz)
- Alfred Adler: (Adler'in teorisine göre analiz)
- Calvin Hall: (Hall'un teorisine göre analiz)
- Erik Erikson: (Erikson'un teorisine göre analiz)

ÖNEMLİ: Sadece yukarıdaki formatı kullan. Başka format kullanma. ${language} dilinde yanıt ver.`
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
      timeout: 30000
    });
    
    const analysis = response.data.choices[0].message.content;
    
    res.json({
      success: true,
      analysis: analysis,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({ error: 'Analysis failed' });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
