import { useNavigate } from 'react-router-dom';

export const Blocked: React.FC = () => {
  const navigate = useNavigate();
  
  return (
    <div className="dashboard-container">
      <div className="dashboard-content">
        <h1>Blocked</h1>
        <p>Are you a robot?</p>
        <button onClick={() => navigate('/blocked')}>Yes</button>
        <button onClick={() => navigate('/dashboard')}>No</button>
      </div>
    </div>
  );
};
