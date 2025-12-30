import { useState } from "react";
import "./App.css";
import {
  BarChart, Bar, LineChart, Line,
  XAxis, Tooltip, CartesianGrid, ResponsiveContainer
} from "recharts";

/* =======================
   ATTACK PRESETS
======================= */
const presets = {
  normal: {
    duration: 0, protocol_type: 1, service: 20, flag: 9,
    src_bytes: 200, dst_bytes: 5000, logged_in: 1,
    count: 8, srv_count: 8, serror_rate: 0,
    same_srv_rate: 1, diff_srv_rate: 0
  },
  dos: {
    duration: 0, protocol_type: 1, service: 20, flag: 4,
    src_bytes: 0, dst_bytes: 0, logged_in: 0,
    count: 511, srv_count: 511, serror_rate: 1,
    same_srv_rate: 1, diff_srv_rate: 0
  },
  probe: {
    duration: 0, protocol_type: 1, service: 20, flag: 9,
    src_bytes: 10, dst_bytes: 0, logged_in: 0,
    count: 120, srv_count: 30, serror_rate: 0,
    same_srv_rate: 0.1, diff_srv_rate: 0.9
  }
};

/* =======================
   EXPLAINABLE AI
======================= */
function explainPrediction(form, prediction) {
  const reasons = [];

  if (prediction === "Normal") {
    reasons.push("Traffic behavior matches normal network patterns.");
    return reasons;
  }

  if (form.serror_rate > 0.5)
    reasons.push("High SYN error rate detected.");

  if (form.diff_srv_rate > 0.7)
    reasons.push("Service variation indicates scanning behavior.");

  if (form.logged_in === 0)
    reasons.push("Unauthenticated access detected.");

  if (form.count > 100)
    reasons.push("Excessive connections to target host.");

  return reasons;
}

/* =======================
   SHAP-STYLE FEATURE IMPACT
======================= */
function shapLikeExplanation(form) {
  const impacts = [];

  if (form.serror_rate > 0.5)
    impacts.push({ feature: "serror_rate", impact: "High", reason: "SYN flooding" });

  if (form.count > 100)
    impacts.push({ feature: "count", impact: "High", reason: "Connection spike" });

  if (form.diff_srv_rate > 0.7)
    impacts.push({ feature: "diff_srv_rate", impact: "Medium", reason: "Port scanning" });

  if (form.logged_in === 0)
    impacts.push({ feature: "logged_in", impact: "Medium", reason: "No authentication" });

  return impacts;
}

export default function App() {
  const [form, setForm] = useState(presets.normal);
  const [result, setResult] = useState("");
  const [risk, setRisk] = useState(0);
  const [explanation, setExplanation] = useState([]);
  const [shapData, setShapData] = useState([]);
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(false);

  const handleChange = (e) => {
    setForm({ ...form, [e.target.name]: Number(e.target.value) });
  };

  const loadPreset = (type) => {
    setForm(presets[type]);
    setResult("");
    setRisk(0);
    setExplanation([]);
    setShapData([]);
  };

  /* =======================
     EXPORT CSV
  ======================= */
  const exportCSV = () => {
    if (history.length === 0) return;

    const headers = ["Time", "Attack", "Risk", "Connections", "ErrorRate"];
    const rows = history.map(h =>
      [h.time, h.attack, h.risk, h.count, h.errorRate].join(",")
    );

    const csv = [headers.join(","), ...rows].join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);

    const a = document.createElement("a");
    a.href = url;
    a.download = "attack_history.csv";
    a.click();
    URL.revokeObjectURL(url);
  };

  /* =======================
     PREDICTION
  ======================= */
  const predict = async () => {
    setLoading(true);

    const payload = {
      ...form,
      land: 0, wrong_fragment: 0, urgent: 0, hot: 0,
      num_failed_logins: 0, num_compromised: 0,
      root_shell: 0, su_attempted: 0, num_root: 0,
      num_file_creations: 0, num_shells: 0,
      num_access_files: 0, num_outbound_cmds: 0,
      is_host_login: 0, is_guest_login: 0,
      srv_serror_rate: form.serror_rate,
      rerror_rate: 0, srv_rerror_rate: 0,
      srv_diff_host_rate: 0,
      dst_host_count: 255,
      dst_host_srv_count: 255,
      dst_host_same_srv_rate: form.same_srv_rate,
      dst_host_diff_srv_rate: form.diff_srv_rate,
      dst_host_same_src_port_rate: 0.04,
      dst_host_srv_diff_host_rate: 0,
      dst_host_serror_rate: form.serror_rate,
      dst_host_srv_serror_rate: form.serror_rate,
      dst_host_rerror_rate: 0,
      dst_host_srv_rerror_rate: 0
    };

    const res = await fetch("http://127.0.0.1:8000/predict", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    const data = await res.json();
    setResult(data.prediction);

    let riskValue = 15;
    let riskLabel = "Low";

    if (data.prediction === "Probe") {
      riskValue = 55;
      riskLabel = "Medium";
    } else if (data.prediction !== "Normal") {
      riskValue = 90;
      riskLabel = "High";
    }

    setRisk(riskValue);
    setExplanation(explainPrediction(form, data.prediction));
    setShapData(shapLikeExplanation(form));

    setHistory(prev => [
      {
        time: new Date().toLocaleTimeString(),
        attack: data.prediction,
        risk: riskLabel,
        count: form.count,
        errorRate: Math.round(form.serror_rate * 100) + "%"
      },
      ...prev
    ]);

    setLoading(false);
  };

  const barData = [
    { name: "Connections", value: form.count },
    { name: "Services", value: form.srv_count },
    { name: "Error Rate", value: Math.round(form.serror_rate * 100) }
  ];

  return (
    <div className="app">
      <div className="dashboard">

        {/* LEFT PANEL */}
        <div className="panel left">
          <h2>⚙️ Traffic Input</h2>

          <div className="preset-buttons">
            <button onClick={() => loadPreset("normal")}>Normal</button>
            <button className="dos" onClick={() => loadPreset("dos")}>DoS</button>
            <button className="probe" onClick={() => loadPreset("probe")}>Probe</button>
          </div>

          <div className="form-grid">
            {Object.keys(form).map((k) => (
              <div className="field" key={k}>
                <label>{k}</label>
                <input name={k} value={form[k]} onChange={handleChange} />
              </div>
            ))}
          </div>

          <button className="predict" onClick={predict}>
            Analyze Traffic
          </button>
        </div>

        {/* RIGHT PANEL */}
        <div className="panel right">
          <h2>📊 Detection Dashboard</h2>

          {loading && <p className="loading">Analyzing...</p>}

          {result && (
            <>
              <div className={`result ${result.toLowerCase()}`}>
                <span>Detection Result</span>
                <h2>{result}</h2>
              </div>

              {/* Risk */}
              <div className="risk">
                <span>Risk Level</span>
                <div className="risk-bar">
                  <div className="risk-fill" style={{ width: `${risk}%` }} />
                </div>
                <small>{risk}% Risk</small>
              </div>

              {/* Explain */}
              <div className="explain">
                <h3>🧠 Why detected</h3>
                <ul>{explanation.map((r, i) => <li key={i}>{r}</li>)}</ul>
              </div>

              {/* SHAP */}
              <div className="explain">
                <h3>📌 Feature Impact (SHAP-style)</h3>
                <ul>
                  {shapData.map((s, i) => (
                    <li key={i}>
                      <strong>{s.feature}</strong> → {s.impact} ({s.reason})
                    </li>
                  ))}
                </ul>
              </div>

              {/* Bar Chart */}
              <div className="chart">
                <ResponsiveContainer width="100%" height={200}>
                  <BarChart data={barData}>
                    <XAxis dataKey="name" />
                    <Tooltip />
                    <Bar dataKey="value" fill="#38bdf8" />
                  </BarChart>
                </ResponsiveContainer>
              </div>

              {/* Line Chart */}
              {history.length > 1 && (
                <div className="chart">
                  <h3>📈 Risk Trend</h3>
                  <ResponsiveContainer width="100%" height={220}>
                    <LineChart data={[...history].reverse()}>
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis dataKey="time" />
                      <Tooltip />
                      <Line dataKey="count" stroke="#22c55e" />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              )}

              {/* History */}
              <div className="history">
                <h3>📜 Attack History</h3>

                <table>
                  <thead>
                    <tr>
                      <th>Time</th><th>Attack</th><th>Risk</th>
                      <th>Connections</th><th>Error</th>
                    </tr>
                  </thead>
                  <tbody>
                    {history.map((h, i) => (
                      <tr key={i}>
                        <td>{h.time}</td>
                        <td className={`tag ${h.attack.toLowerCase()}`}>{h.attack}</td>
                        <td>{h.risk}</td>
                        <td>{h.count}</td>
                        <td>{h.errorRate}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>

                <button className="export" onClick={exportCSV}>📥 Export CSV</button>
                <button className="clear" onClick={() => setHistory([])}>Clear</button>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
