import React, { useState, useEffect } from "react";

const getCookie = (name: string) => {
  const cookie: Record<string, string> = {};
  document.cookie.split(';').forEach(function (el) {
    const split = el.split('=');
    cookie[split[0].trim()] = split.slice(1).join('=');
  });
  return cookie[name];
};

export const Leaderboard: React.FC = () => {
  const [leaderboardData, setLeaderboardData] = useState<any[]>([]);
  const [isLoadingLeaderboard, setIsLoadingLeaderboard] = useState(false);

  const fetchLeaderboard = async () => {
    setIsLoadingLeaderboard(true);
    try {
      const response = await fetch('http://localhost:8787/api/leaderboard', {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${getCookie('stytch_session')}`,
        }
      });
      
      if (response.ok) {
        const data = await response.json();
        setLeaderboardData(data.leaderboard);
      } else {
        console.error('Failed to fetch leaderboard');
        setLeaderboardData([]);
      }
    } catch (error) {
      console.error('Error fetching leaderboard:', error);
      setLeaderboardData([]);
    } finally {
      setIsLoadingLeaderboard(false);
    }
  };

  // Fetch leaderboard on component mount
  useEffect(() => {
    fetchLeaderboard();
  }, []);

  return (
    <div style={{ marginTop: '40px', textAlign: 'center' }}>
      <h2 style={{ color: '#2c3e50', marginBottom: '20px' }}>🏆 Leaderboard</h2>
      
      {isLoadingLeaderboard ? (
        <div style={{ padding: '20px', color: '#666' }}>Loading leaderboard...</div>
      ) : leaderboardData.length > 0 ? (
        <div style={{ 
          display: 'inline-block', 
          maxWidth: '800px', 
          width: '100%',
          overflowX: 'auto'
        }}>
          <table style={{
            width: '100%',
            borderCollapse: 'collapse',
            backgroundColor: 'white',
            borderRadius: '8px',
            overflow: 'hidden',
            boxShadow: '0 2px 8px rgba(0,0,0,0.1)'
          }}>
            <thead>
              <tr style={{ backgroundColor: '#f8f9fa' }}>
                <th style={{ 
                  padding: '12px 16px', 
                  textAlign: 'left', 
                  borderBottom: '2px solid #dee2e6',
                  fontWeight: 'bold',
                  color: '#495057'
                }}>
                  Rank
                </th>
                <th style={{ 
                  padding: '12px 16px', 
                  textAlign: 'left', 
                  borderBottom: '2px solid #dee2e6',
                  fontWeight: 'bold',
                  color: '#495057'
                }}>
                  Name
                </th>
                <th style={{ 
                  padding: '12px 16px', 
                  textAlign: 'left', 
                  borderBottom: '2px solid #dee2e6',
                  fontWeight: 'bold',
                  color: '#495057'
                }}>
                  Organization
                </th>
                <th style={{ 
                  padding: '12px 16px', 
                  textAlign: 'right', 
                  borderBottom: '2px solid #dee2e6',
                  fontWeight: 'bold',
                  color: '#495057'
                }}>
                  Cookies Baked
                </th>
              </tr>
            </thead>
            <tbody>
              {leaderboardData.map((entry, index) => (
                <tr key={index} style={{ 
                  borderBottom: '1px solid #dee2e6',
                  backgroundColor: index % 2 === 0 ? '#ffffff' : '#f8f9fa'
                }}>
                  <td style={{ 
                    padding: '12px 16px', 
                    fontWeight: index < 3 ? 'bold' : 'normal',
                    color: index < 3 ? '#ffc107' : '#495057'
                  }}>
                    {index + 1}
                  </td>
                  <td style={{ 
                    padding: '12px 16px',
                    fontWeight: 'bold',
                    color: '#495057'
                  }}>
                    {entry.name}
                  </td>
                  <td style={{ 
                    padding: '12px 16px',
                    color: '#6c757d'
                  }}>
                    {entry.organization}
                  </td>
                  <td style={{ 
                    padding: '12px 16px', 
                    textAlign: 'right',
                    fontWeight: 'bold',
                    color: '#28a745'
                  }}>
                    {entry.baked || 0}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div style={{ padding: '10px', color: '#666' }}>No leaderboard data available</div>
      )}
      <div style={{ marginTop: '0px' }}>
        <button
            onClick={fetchLeaderboard}
            disabled={isLoadingLeaderboard}
            style={{
            marginTop: '50px',
            fontSize: '0.9rem',
            padding: '8px 16px',
            border: 'none',
            borderRadius: '6px',
            cursor: isLoadingLeaderboard ? 'not-allowed' : 'pointer',
            backgroundColor: isLoadingLeaderboard ? '#cccccc' : '#6c757d',
            color: 'white',
            fontWeight: 'bold',
            transition: 'all 0.2s ease'
            }}
        >
            {isLoadingLeaderboard ? 'Refreshing...' : '🔄 Refresh Leaderboard'}
        </button>
      </div>
    </div>
  );
}; 