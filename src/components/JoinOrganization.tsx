import { useNavigate } from 'react-router-dom';
import { Leaderboard } from "./Leaderboard";

export const JoinOrganization: React.FC = () => {
  const navigate = useNavigate();
  
  const buttonStyle = {
    fontSize: '4rem',
    padding: '20px 40px',
    margin: '15px',
    border: 'none',
    borderRadius: '15px',
    cursor: 'pointer',
    transition: 'all 0.3s ease',
    backgroundColor: '#f8f9fa',
    boxShadow: '0 4px 6px rgba(0, 0, 0, 0.1)',
    minWidth: '120px',
    minHeight: '120px',
    display: 'flex',
    flexDirection: 'column' as const,
    alignItems: 'center',
    justifyContent: 'center',
    gap: '10px'
  };

  const buttonHoverStyle = {
    transform: 'translateY(-5px)',
    boxShadow: '0 8px 25px rgba(0, 0, 0, 0.15)',
    backgroundColor: '#ffffff'
  };

  const labelStyle = {
    fontSize: '1rem',
    fontWeight: 'bold',
    color: '#333',
    marginTop: '5px'
  };

  return (
    <div className="dashboard-container">
      <div className="dashboard-content">
        <h1 style={{ 
          fontSize: '2.5rem', 
          marginBottom: '40px', 
          color: '#2c3e50',
          textAlign: 'center'
        }}>
          What do you want to bake today?
        </h1>
        
        <div style={{ 
          display: 'flex', 
          flexWrap: 'wrap', 
          justifyContent: 'center', 
          gap: '20px',
          maxWidth: '600px'
        }}>
          <button 
            onClick={() => navigate('/cookie')}
            style={buttonStyle}
            onMouseEnter={(e) => {
              Object.assign(e.currentTarget.style, buttonHoverStyle);
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.transform = '';
              e.currentTarget.style.boxShadow = buttonStyle.boxShadow;
              e.currentTarget.style.backgroundColor = buttonStyle.backgroundColor;
            }}
          >
            🍪
            <span style={labelStyle}>Cookies</span>
          </button>
          
          <button 
            onClick={() => navigate('/cake')}
            style={buttonStyle}
            onMouseEnter={(e) => {
              Object.assign(e.currentTarget.style, buttonHoverStyle);
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.transform = '';
              e.currentTarget.style.boxShadow = buttonStyle.boxShadow;
              e.currentTarget.style.backgroundColor = buttonStyle.backgroundColor;
            }}
          >
            🍰
            <span style={labelStyle}>Cakes</span>
          </button>
          
          <button 
            onClick={() => navigate('/pie')}
            style={buttonStyle}
            onMouseEnter={(e) => {
              Object.assign(e.currentTarget.style, buttonHoverStyle);
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.transform = '';
              e.currentTarget.style.boxShadow = buttonStyle.boxShadow;
              e.currentTarget.style.backgroundColor = buttonStyle.backgroundColor;
            }}
          >
            🥧
            <span style={labelStyle}>Pies</span>
          </button>
        </div>
      </div>
      <Leaderboard />
    </div>
  );
};
