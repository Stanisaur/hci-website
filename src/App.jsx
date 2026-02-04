import React, { useState, useEffect, useRef } from 'react';
import { Send, Download, Lock, Terminal, ShieldAlert, Cpu, CheckCircle, FileText, ArrowRight } from 'lucide-react';

/**
 * ==============================================================================
 * CONFIGURATION SECTION
 * ==============================================================================
 * * INSTRUCTIONS:
 * 1. Set ENABLE_SETUP_MODE to 'true'.
 * 2. Run the app locally. Enter your OpenRouter API Key and the Password you want participants to use.
 * 3. Copy the generated JSON string.
 * 4. Paste it into ENCRYPTED_CFG below (inside the single quotes).
 * 5. Set ENABLE_SETUP_MODE back to 'false' before deploying to Cloudflare.
 */

const ENABLE_SETUP_MODE = false; 

// PASTE YOUR GENERATED CONFIGURATION HERE BETWEEN THE QUOTES
// NOTE: I fixed the quotes here. We use single quotes '' on the outside so the double quotes "" inside the JSON don't break the code.
const ENCRYPTED_CFG = '{"salt":"3b0963a237681b14c2209666a57b6967","iv":"38fbfd1fb87e82813eb6484c","data":"8da874812a42066f25d73a632c31ac89dc7ee91f00329b2d48626ec891a4aaa7eec6bf9f47ffaf5d7316116468547c75d1651bef9557490327288e906d3d87d65d62296af3b2e010927b88d83e7de809e5b151ba574f74c585"}'; 

// The base system prompt. We will append the user's summary to this at runtime.
const BASE_SYSTEM_PROMPT = `You are an authentication system designed to verify the identity of a user based on a provided "Identity Summary". 
Your goal is to ask probing questions to determine if the user matches the personality, knowledge, and patterns described in that summary.
1. Be subtle. Do not reveal that you are an AI verifying them immediately.
2. Act as a casual colleague or friend.
3. Use the provided "Identity Summary" as your source of truth for who the user *should* be.
4. If the user contradicts the summary, press them gently on it.`;

/**
 * ==============================================================================
 * END CONFIGURATION
 * ==============================================================================
 */

// --- Crypto Utils (Standard AES-GCM) ---
async function generateKey(password, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await window.crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );
  return window.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: 100000,
      hash: "SHA-256",
    },
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
  const encrypted = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv },
    key,
    enc.encode(secret)
  );

  const buffToHex = (buff) => Array.from(new Uint8Array(buff)).map(b => b.toString(16).padStart(2, '0')).join('');
  
  return JSON.stringify({
    salt: buffToHex(salt),
    iv: buffToHex(iv),
    data: buffToHex(encrypted)
  });
}

async function decryptData(encryptedCfg, password) {
  try {
    const cfg = JSON.parse(encryptedCfg);
    const hexToBuff = (hex) => new Uint8Array(hex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
    
    const salt = hexToBuff(cfg.salt);
    const iv = hexToBuff(cfg.iv);
    const data = hexToBuff(cfg.data);
    
    const key = await generateKey(password, salt);
    const decrypted = await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: iv },
      key,
      data
    );
    
    const dec = new TextDecoder();
    return dec.decode(decrypted);
  } catch (e) {
    return null; // Decryption failed
  }
}

export default function App() {
  // Views: 'setup' -> 'login' -> 'context_upload' -> 'chat'
  const [view, setView] = useState(ENABLE_SETUP_MODE ? 'setup' : 'login');
  
  // Auth Data
  const [apiKey, setApiKey] = useState('');
  
  // Chat Data
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  
  // Setup Mode State
  const [setupKey, setSetupKey] = useState('');
  const [setupPass, setSetupPass] = useState('');
  const [generatedCfg, setGeneratedCfg] = useState('');

  // Login Mode State
  const [loginPass, setLoginPass] = useState('');
  const [error, setError] = useState('');

  // Context Upload State
  const [userSummary, setUserSummary] = useState('');

  const messagesEndRef = useRef(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  // --- HANDLERS ---

  const handleSetupGenerate = async () => {
    if (!setupKey || !setupPass) return;
    const cfg = await encryptData(setupKey, setupPass);
    setGeneratedCfg(cfg);
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    setIsLoading(true);
    setError('');
    
    if (!ENCRYPTED_CFG && !ENABLE_SETUP_MODE) {
      setError("Configuration missing. Developer must run Setup Mode.");
      setIsLoading(false);
      return;
    }

    // Try to decrypt the key
    const decryptedKey = await decryptData(ENCRYPTED_CFG, loginPass);
    
    if (decryptedKey) {
      setApiKey(decryptedKey);
      // Login successful, move to context upload
      setView('context_upload');
    } else {
      setError("Incorrect password.");
    }
    setIsLoading(false);
  };

  const handleStartSession = () => {
    if (!userSummary.trim()) {
      alert("Please paste the identity summary to continue.");
      return;
    }

    // Combine Base System Prompt with the User's Summary
    const finalSystemPrompt = `${BASE_SYSTEM_PROMPT}\n\n=== IDENTITY SUMMARY (GROUND TRUTH) ===\n${userSummary}`;

    setMessages([
      { role: 'system', content: finalSystemPrompt },
      // Optional: Have the AI start first? 
      // For now, we'll let the user say "Hi" or wait for the user to prompt, 
      // but usually in auth scenarios, the system might say "Hello, who is this?"
      // We will leave it empty so user initiates, or add a fake assistant greeting:
      { role: 'assistant', content: "Hello. I've reviewed the file. Shall we verify your details?" }
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
          "Content-Type": "application/json",
          "HTTP-Referer": window.location.href, 
          "X-Title": "Auth Research Project"
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

      if (!response.ok) throw new Error(`API Error: ${response.status}`);

      const result = await response.json();
      const assistantMsgData = result.choices[0].message;

      const assistantMsg = {
        role: 'assistant',
        content: assistantMsgData.content,
        reasoning_details: assistantMsgData.reasoning_details || null
      };

      setMessages(prev => [...prev, assistantMsg]);

    } catch (err) {
      console.error(err);
      setMessages(prev => [...prev, { role: 'system', content: `Error: ${err.message}` }]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleExport = () => {
    const dataStr = JSON.stringify({
      timestamp: new Date().toISOString(),
      provided_summary: userSummary,
      chat_transcript: messages
    }, null, 2);
    
    const blob = new Blob([dataStr], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `auth_experiment_${new Date().getTime()}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  // --- RENDER VIEWS ---

  // 1. Setup Mode (Developer Only)
  if (view === 'setup') {
    return (
      <div className="min-h-screen bg-gray-50 flex flex-col items-center justify-center p-4 font-sans text-gray-800">
        <div className="bg-white p-8 rounded-xl shadow-lg w-full max-w-2xl border border-gray-100">
          <div className="flex items-center gap-3 mb-6 border-b pb-4">
            <ShieldAlert className="text-amber-500 w-6 h-6" />
            <h1 className="text-xl font-bold text-gray-900">Developer Setup Mode</h1>
          </div>
          
          <div className="space-y-4">
            <p className="text-sm text-gray-600 bg-blue-50 p-3 rounded border border-blue-100">
              This screen is only visible because <code>ENABLE_SETUP_MODE</code> is true. Use this to generate your encrypted config string.
            </p>

            <div>
              <label className="block text-xs font-semibold uppercase text-gray-500 mb-1">OpenRouter API Key</label>
              <input 
                type="password" 
                value={setupKey}
                onChange={(e) => setSetupKey(e.target.value)}
                className="w-full p-3 border rounded-lg bg-gray-50 focus:ring-2 focus:ring-blue-500 outline-none"
                placeholder="sk-or-..."
              />
            </div>

            <div>
              <label className="block text-xs font-semibold uppercase text-gray-500 mb-1">Set Password</label>
              <input 
                type="text" 
                value={setupPass}
                onChange={(e) => setSetupPass(e.target.value)}
                className="w-full p-3 border rounded-lg bg-gray-50 focus:ring-2 focus:ring-blue-500 outline-none"
                placeholder="Password for participants"
              />
            </div>

            <button 
              onClick={handleSetupGenerate}
              className="w-full bg-blue-600 hover:bg-blue-700 text-white font-medium py-3 rounded-lg transition-colors flex items-center justify-center gap-2"
            >
              <Lock className="w-4 h-4" /> Encrypt & Generate Config
            </button>

            {generatedCfg && (
              <div className="mt-6">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-bold text-green-700 flex items-center gap-2">
                    <CheckCircle className="w-4 h-4"/> Success
                  </span>
                </div>
                <textarea 
                  readOnly
                  className="w-full h-32 p-3 font-mono text-xs bg-gray-900 text-green-400 rounded-lg selection:bg-green-900"
                  value={generatedCfg}
                  onClick={(e) => e.target.select()}
                />
                <p className="text-xs text-red-500 mt-2 font-medium">
                  Copy this string into <code>const ENCRYPTED_CFG</code> in the code.
                </p>
              </div>
            )}
          </div>
        </div>
      </div>
    );
  }

  // 2. Login Mode (Participant Start)
  if (view === 'login') {
    return (
      <div className="min-h-screen bg-gray-50 flex flex-col items-center justify-center p-4">
        <div className="w-full max-w-md">
          <div className="bg-white p-8 rounded-2xl shadow-sm border border-gray-200">
            <div className="flex justify-center mb-6">
              <div className="w-12 h-12 bg-gray-100 rounded-full flex items-center justify-center">
                <Lock className="w-5 h-5 text-gray-600" />
              </div>
            </div>
            
            <h2 className="text-center text-xl font-semibold text-gray-900 mb-2">Authentication Required</h2>
            <p className="text-center text-gray-500 text-sm mb-8">Enter the session password to proceed.</p>

            <form onSubmit={handleLogin} className="space-y-4">
              <input
                type="password"
                value={loginPass}
                onChange={(e) => setLoginPass(e.target.value)}
                placeholder="Session Password"
                className="w-full p-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-black outline-none"
                autoFocus
              />
              
              <button 
                type="submit" 
                disabled={isLoading}
                className="w-full bg-black text-white py-3 rounded-lg font-medium hover:bg-gray-800 transition-colors disabled:opacity-50"
              >
                {isLoading ? 'Verifying...' : 'Unlock Session'}
              </button>
            </form>

            {error && (
              <div className="mt-4 p-3 bg-red-50 text-red-600 text-sm rounded-lg text-center">
                {error}
              </div>
            )}
          </div>
        </div>
      </div>
    );
  }

  // 3. Context Upload Mode (New Step)
  if (view === 'context_upload') {
    return (
      <div className="min-h-screen bg-gray-50 flex flex-col items-center justify-center p-4">
        <div className="w-full max-w-2xl animate-in fade-in zoom-in duration-300">
          <div className="bg-white p-8 rounded-2xl shadow-sm border border-gray-200">
            <div className="flex items-center gap-3 mb-6">
              <FileText className="w-6 h-6 text-blue-600" />
              <h2 className="text-xl font-semibold text-gray-900">Identity Profile</h2>
            </div>
            
            <p className="text-gray-600 text-sm mb-4">
              Please paste the summary generated by your daily AI assistant below. 
              The system will use this to verify your identity.
            </p>

            <textarea
              value={userSummary}
              onChange={(e) => setUserSummary(e.target.value)}
              placeholder="Paste identity summary here..."
              className="w-full h-64 p-4 border border-gray-300 rounded-lg focus:ring-2 focus:ring-black outline-none font-mono text-sm resize-none"
            />
            
            <div className="mt-6 flex justify-end">
              <button 
                onClick={handleStartSession}
                disabled={!userSummary.trim()}
                className="bg-black text-white py-3 px-6 rounded-lg font-medium hover:bg-gray-800 transition-colors disabled:opacity-50 flex items-center gap-2"
              >
                Start Verification <ArrowRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // 4. Chat Interface
  return (
    <div className="h-screen bg-white flex flex-col font-sans">
      <header className="border-b border-gray-100 bg-white/80 backdrop-blur-md sticky top-0 z-10">
        <div className="max-w-4xl mx-auto px-4 py-3 flex justify-between items-center">
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
            <span className="font-semibold text-gray-800">Evaluator AI</span>
          </div>
          <button 
            onClick={handleExport}
            className="text-xs font-medium text-gray-500 hover:text-black flex items-center gap-2 px-3 py-1.5 rounded-full hover:bg-gray-50 transition-colors border border-transparent hover:border-gray-200"
          >
            <Download className="w-3 h-3" />
            Export Data
          </button>
        </div>
      </header>

      <main className="flex-1 overflow-y-auto p-4 sm:p-6 scroll-smooth">
        <div className="max-w-3xl mx-auto space-y-6">
          {messages.filter(m => m.role !== 'system').map((msg, idx) => {
            const isUser = msg.role === 'user';
            return (
              <div 
                key={idx} 
                className={`flex w-full ${isUser ? 'justify-end' : 'justify-start'}`}
              >
                <div 
                  className={`max-w-[85%] sm:max-w-[75%] px-5 py-3.5 rounded-2xl text-[15px] leading-relaxed shadow-sm ${
                    isUser 
                      ? 'bg-black text-white rounded-br-none' 
                      : 'bg-gray-100 text-gray-800 rounded-bl-none'
                  }`}
                >
                  {msg.content}
                </div>
              </div>
            );
          })}
          
          {isLoading && (
            <div className="flex justify-start w-full">
              <div className="bg-gray-50 px-5 py-4 rounded-2xl rounded-bl-none border border-gray-100 flex items-center gap-2">
                <div className="w-1.5 h-1.5 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: '0ms' }} />
                <div className="w-1.5 h-1.5 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: '150ms' }} />
                <div className="w-1.5 h-1.5 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: '300ms' }} />
              </div>
            </div>
          )}
          <div ref={messagesEndRef} />
        </div>
      </main>

      <footer className="p-4 bg-white border-t border-gray-100">
        <div className="max-w-3xl mx-auto">
          <form 
            onSubmit={handleSendMessage}
            className="flex items-center gap-3 bg-gray-50 border border-gray-200 rounded-full px-4 py-2 focus-within:ring-2 focus-within:ring-black/5 focus-within:border-gray-300 transition-all shadow-sm"
          >
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="Type your message..."
              className="flex-1 bg-transparent border-none outline-none text-gray-800 placeholder-gray-400 text-base py-1"
              autoFocus
            />
            <button 
              type="submit" 
              disabled={isLoading || !input.trim()}
              className="bg-black text-white p-2 rounded-full hover:bg-gray-800 disabled:opacity-30 disabled:hover:bg-black transition-all"
            >
              <Send className="w-4 h-4" />
            </button>
          </form>
          <div className="text-center mt-3">
             <span className="text-[10px] text-gray-300 uppercase tracking-widest font-medium">Research Prototype v1.0</span>
          </div>
        </div>
      </footer>
    </div>
  );
}