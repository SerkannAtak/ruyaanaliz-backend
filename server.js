const express = require('express');
const axios = require('axios');
const cors = require('cors');

const app = express();
// Railway otomatik olarak PORT environment variable'ını set eder
const PORT = process.env.PORT || 8080; // 8080 olarak değiştir

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
          content: `Sen bir rüya analiz uzmanısın. ${language} dilinde yanıt ver.`
        },
        {
          role: "user",
          content: dream
        }
      ],
      max_tokens: 2000
    }, {
      headers: {
        'Authorization': `Bearer ${process.env.GROQ_API_KEY}`,
        'Content-Type': 'application/json'
      }
    });
    
    res.json({
      success: true,
      analysis: response.data.choices[0].message.content
    });
  } catch (error) {
    res.status(500).json({ error: 'Analysis failed' });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
