import { useEffect, useState } from "react";
import "./App.css";

function App() {
  const [health, setHealth] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    async function checkBackend() {
      try {
        const response = await fetch("/api/health");

        if (!response.ok) {
          throw new Error("Backend health check failed");
        }

        const data = await response.json();
        setHealth(data);
      } catch (err) {
        setError(err.message);
      }
    }

    checkBackend();
  }, []);

  return (
    <main className="app">
      <section className="status-card">
        <h1>RAMAH-NETWATCH</h1>
        <p>Network Security Monitoring Platform</p>

        <div className="status">
          {health ? (
            <>
              <span className="indicator online"></span>
              <strong>Backend Online</strong>
              <p>{health.message}</p>
            </>
          ) : error ? (
            <>
              <span className="indicator offline"></span>
              <strong>Backend Offline</strong>
              <p>{error}</p>
            </>
          ) : (
            <p>Checking backend connection...</p>
          )}
        </div>
      </section>
    </main>
  );
}

export default App;