import React, { useState, useEffect, useRef } from 'react';
import { Send, Download, Lock, ShieldAlert, CheckCircle, FileText, ArrowRight, Copy, Info } from 'lucide-react';

/**
 * ==============================================================================
 * CONFIGURATION SECTION
 * ==============================================================================
 */

const ENABLE_SETUP_MODE = false; 

// PASTE YOUR GENERATED CONFIGURATION HERE BETWEEN THE QUOTES
const ENCRYPTED_CFG = '{"salt":"3b0963a237681b14c2209666a57b6967","iv":"38fbfd1fb87e82813eb6484c","data":"8da874812a42066f25d73a632c31ac89dc7ee91f00329b2d48626ec891a4aaa7eec6bf9f47ffaf5d7316116468547c75d1651bef9557490327288e906d3d87d65d62296af3b2e010927b88d83e7de809e5b151ba574f74c585"}'; 

const BASE_SYSTEM_PROMPT = `You are an authentication system designed to verify the identity of a user based on a provided "Identity Summary". 
Your goal is to ask probing questions to determine if the user matches the personality, knowledge, and patterns described in that summary.
1. Be subtle. Do not reveal that you are an AI verifying them immediately.
2. Act as a casual colleague or friend.
3. Use the provided "Identity Summary" as your source of truth for who the user *should* be.
4. If the user contradicts the summary, press them gently on it.`;

const EXTRACTION_PROMPT = `# Profile Extraction Prompt

You are a behavioral analyst and digital archivist. I am conducting research on identity authentication. Please analyze our entire interaction history, including any stored memory or persona data you have on me. 

Create a Comprehensive Identity Profile for me that includes the following:

1. Linguistic Fingerprint: Describe my sentence structure, vocabulary preferences, and any recurring idioms or unique ways I frame questions.
2. Knowledge Domains: Identify the specific topics I am most knowledgeable in and the "depth" of that knowledge.
3. Thematic Consistency: List three to five recurring themes or problems I have consistently brought to you over time.
4. Obscure Preferences: Note any highly specific preferences I have mentioned regarding work, lifestyle, or technology that would not be publicly known.
5. Contextual Anchors: Identify specific dates, locations, or life events I have shared that could serve as "secret" verification points.

Present this as a structured report in .md format. Do not include generic observations; focus only on what makes my profile unique compared to a standard user.`;

/**
 * ==============================================================================
 * END CONFIGURATION
 * ==============================================================================
 */

async function generateKey(password, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await window.crypto.subtle.importKey(
    "raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveKey"]
  );
  return window.crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: salt, iterations: 100000, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
}

async function encryptData(secret, password) {
  const salt = window.crypto.getRandomValues(new Uint8Array(16));
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const key = await generateKey(password, salt);
  const enc = new TextEncoder();
  const encrypted = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, key, enc.encode(secret));
  const buffToHex = (buff) => Array.from(new Uint8Array(buff)).map(b => b.toString(16).padStart(2, '0')).join('');
  return JSON.stringify({ salt: buffToHex(salt), iv: buffToHex(iv), data: buffToHex(encrypted) });
}

async function decryptData(encryptedCfg, password) {
  try {
    const cfg = JSON.parse(encryptedCfg);
    const hexToBuff = (hex) => new Uint8Array(hex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
    const salt = hexToBuff(cfg.salt);
    const iv = hexToBuff(cfg.iv);
    const data = hexToBuff(cfg.data);
    const key = await generateKey(password, salt);
    const decrypted = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, key, data);
    return new TextDecoder().decode(decrypted);
  } catch (e) { return null; }
}

export default function App() {
  const [view, setView] = useState(ENABLE_SETUP_MODE ? 'setup' : 'login');
  const [apiKey, setApiKey] = useState('');
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [setupKey, setSetupKey] = useState('');
  const [setupPass, setSetupPass] = useState('');
  const [generatedCfg, setGeneratedCfg] = useState('');
  const [loginPass, setLoginPass] = useState('');
  const [error, setError] = useState('');
  const [userSummary, setUserSummary] = useState('');
  const [copyFeedback, setCopyFeedback] = useState(false);

  const messagesEndRef = useRef(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const handleCopyPrompt = () => {
    const textArea = document.createElement("textarea");
    textArea.value = EXTRACTION_PROMPT;
    document.body.appendChild(textArea);
    textArea.select();
    try {
      document.execCommand('copy');
      setCopyFeedback(true);
      setTimeout(() => setCopyFeedback(false), 2000);
    } catch (err) {
      console.error('Fallback copy failed', err);
    }
    document.body.removeChild(textArea);
  };

  const handleSetupGenerate = async () => {
    if (!setupKey || !setupPass) return;
    const cfg = await encryptData(setupKey, setupPass);
    setGeneratedCfg(cfg);
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    setIsLoading(true);
    setError('');
    const decryptedKey = await decryptData(ENCRYPTED_CFG, loginPass);
    if (decryptedKey) {
      setApiKey(decryptedKey);
      setView('context_upload');
    } else {
      setError("Incorrect password.");
    }
    setIsLoading(false);
  };

  const handleStartSession = () => {
    if (!userSummary.trim()) return;
    const finalSystemPrompt = `${BASE_SYSTEM_PROMPT}\n\n=== IDENTITY SUMMARY (GROUND TRUTH) ===\n${userSummary}`;
    setMessages([
      { role: 'system', content: finalSystemPrompt },
      { role: 'assistant', content: "Hello. I have reviewed your profile. Shall we begin the verification process?" }
    ]);
    setView('chat');
  };

  const handleSendMessage = async (e) => {
    e.preventDefault();
    if (!input.trim() || isLoading) return;
    const userMsg = { role: 'user', content: input };
    const newHistory = [...messages, userMsg];
    setMessages(newHistory);
    setInput('');
    setIsLoading(true);

    try {
      const response = await fetch("https://openrouter.ai/api/v1/chat/completions", {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${apiKey}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          "model": "moonshotai/kimi-k2.5",
          "messages": newHistory.map(m => ({ 
            role: m.role, 
            content: m.content,
            ...(m.reasoning_details && { reasoning_details: m.reasoning_details }) 
          })),
          "reasoning": { "enabled": true }
        })
      });
      const result = await response.json();
      const assistantMsgData = result.choices[0].message;
      setMessages(prev => [...prev, {
        role: 'assistant',
        content: assistantMsgData.content,
        reasoning_details: assistantMsgData.reasoning_details || null
      }]);
    } catch (err) {
      setMessages(prev => [...prev, { role: 'system', content: `Error: ${err.message}` }]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleExport = () => {
    const dataStr = JSON.stringify({ timestamp: new Date().toISOString(), provided_summary: userSummary, chat_transcript: messages }, null, 2);
    const blob = new Blob([dataStr], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `auth_experiment_${new Date().getTime()}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  if (view === 'setup') {
    return (
      <div className="min-h-screen bg-gray-50 flex flex-col items-center justify-center p-4">
        <div className="bg-white p-8 rounded-xl shadow-lg w-full max-w-2xl border border-gray-100">
          <h1 className="text-xl font-bold mb-6 flex items-center gap-2"><ShieldAlert className="text-amber-500" /> Developer Setup</h1>
          <div className="space-y-4">
            <input type="password" value={setupKey} onChange={(e) => setSetupKey(e.target.value)} className="w-full p-3 border rounded-lg" placeholder="OpenRouter API Key" />
            <input type="text" value={setupPass} onChange={(e) => setSetupPass(e.target.value)} className="w-full p-3 border rounded-lg" placeholder="Participant Password" />
            <button onClick={handleSetupGenerate} className="w-full bg-blue-600 text-white py-3 rounded-lg flex items-center justify-center gap-2"><Lock size={18} /> Encrypt Key</button>
            {generatedCfg && <textarea readOnly className="w-full h-32 p-3 font-mono text-xs bg-gray-900 text-green-400 rounded-lg mt-4" value={generatedCfg} onClick={(e) => e.target.select()} />}
          </div>
        </div>
      </div>
    );
  }

  if (view === 'login') {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center p-4">
        <div className="bg-white p-8 rounded-2xl shadow-sm border border-gray-200 w-full max-w-md">
          <div className="flex justify-center mb-6"><Lock className="text-gray-400" size={40} /></div>
          <h2 className="text-center text-xl font-semibold mb-8">Experiment Access</h2>
          <form onSubmit={handleLogin} className="space-y-4">
            <input type="password" value={loginPass} onChange={(e) => setLoginPass(e.target.value)} placeholder="Password" className="w-full p-3 border rounded-lg outline-none focus:ring-2 focus:ring-black" />
            <button type="submit" className="w-full bg-black text-white py-3 rounded-lg hover:bg-gray-800 transition-colors">Start Session</button>
          </form>
          {error && <p className="mt-4 text-red-500 text-sm text-center">{error}</p>}
        </div>
      </div>
    );
  }

  if (view === 'context_upload') {
    return (
      <div className="min-h-screen bg-gray-50 flex flex-col items-center justify-center p-4">
        <div className="w-full max-w-2xl bg-white p-8 rounded-2xl shadow-sm border border-gray-200">
          <div className="flex items-center gap-3 mb-6">
            <FileText className="text-blue-600" />
            <h2 className="text-xl font-semibold">Identity Verification</h2>
          </div>
          
          <div className="bg-blue-50 border border-blue-100 p-5 rounded-xl mb-8">
            <h3 className="text-blue-800 font-semibold text-sm flex items-center gap-2 mb-2">
              <Info size={16} /> Step 1: Generate your profile
            </h3>
            <p className="text-blue-700 text-xs mb-4 leading-relaxed">
              Open the AI chatbot you use daily (ChatGPT, Claude, etc.) and paste the prompt below. It will analyze your history to create a behavioral fingerprint.
            </p>
            <div className="relative group">
              <div className="bg-white/60 p-4 rounded-lg text-[11px] font-mono text-gray-600 border border-blue-200 max-h-32 overflow-hidden italic">
                {EXTRACTION_PROMPT.substring(0, 150)}...
              </div>
              <button 
                onClick={handleCopyPrompt}
                className="absolute inset-0 w-full h-full bg-blue-600/90 text-white flex items-center justify-center gap-2 opacity-0 group-hover:opacity-100 transition-opacity rounded-lg font-medium"
              >
                {copyFeedback ? <CheckCircle size={18} /> : <Copy size={18} />}
                {copyFeedback ? 'Prompt Copied!' : 'Copy Extraction Prompt'}
              </button>
            </div>
          </div>

          <div className="space-y-4">
            <h3 className="text-gray-800 font-semibold text-sm flex items-center gap-2">
              <ArrowRight size={16} /> Step 2: Paste profile results
            </h3>
            <textarea
              value={userSummary}
              onChange={(e) => setUserSummary(e.target.value)}
              placeholder="Paste the profile report here..."
              className="w-full h-64 p-4 border rounded-lg focus:ring-2 focus:ring-black outline-none font-mono text-sm"
            />
            <button 
              onClick={handleStartSession}
              disabled={!userSummary.trim()}
              className="w-full bg-black text-white py-4 rounded-lg font-medium flex items-center justify-center gap-2 disabled:opacity-30"
            >
              Verify Identity <ArrowRight size={18} />
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="h-screen flex flex-col bg-white">
      <header className="border-b px-6 py-4 flex justify-between items-center">
        <div className="flex items-center gap-2 text-sm font-semibold text-gray-700">
          <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse" />
          Live Verification Session
        </div>
        <button onClick={handleExport} className="text-xs flex items-center gap-1 text-gray-500 hover:text-black transition-colors">
          <Download size={14} /> Export Logs
        </button>
      </header>

      <main className="flex-1 overflow-y-auto p-6">
        <div className="max-w-3xl mx-auto space-y-6">
          {messages.filter(m => m.role !== 'system').map((msg, i) => (
            <div key={i} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
              <div className={`max-w-[80%] p-4 rounded-2xl ${msg.role === 'user' ? 'bg-black text-white rounded-br-none' : 'bg-gray-100 text-gray-800 rounded-bl-none'}`}>
                <p className="text-[15px] leading-relaxed">{msg.content}</p>
              </div>
            </div>
          ))}
          {isLoading && <div className="text-gray-400 text-xs animate-pulse">AI is thinking...</div>}
          <div ref={messagesEndRef} />
        </div>
      </main>

      <footer className="p-6 border-t bg-white">
        <div className="max-w-3xl mx-auto">
          <form onSubmit={handleSendMessage} className="flex gap-2 bg-gray-50 p-1.5 rounded-full border">
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="Respond to verify..."
              className="flex-1 bg-transparent px-4 outline-none text-[15px]"
            />
            <button type="submit" disabled={isLoading || !input.trim()} className="bg-black text-white p-2.5 rounded-full disabled:opacity-30">
              <Send size={18} />
            </button>
          </form>
        </div>
      </footer>
    </div>
  );
}