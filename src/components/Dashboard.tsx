import { useStytchMemberSession, useStytchOrganization } from "@stytch/react/b2b";
import { useState } from "react";

const getCookie = (name: string) => {
  const cookie: Record<string, string> = {};
  document.cookie.split(';').forEach(function (el) {
    const split = el.split('=');
    cookie[split[0].trim()] = split.slice(1).join('=');
  });
  return cookie[name];
};

export const Dashboard: React.FC = () => {
  const { session } = useStytchMemberSession();
  const { organization } = useStytchOrganization();
  const [cookieCount, setCookieCount] = useState(0);
  const [isFeeding, setIsFeeding] = useState(false);
  const [isRequestingPromotion, setIsRequestingPromotion] = useState(false);
  const [promotionResponse, setPromotionResponse] = useState<any>(null);

  const role = session?.roles.filter((role) => role !== "stytch_member");
  
  const handleCookieClick = () => {
    setCookieCount(prev => prev + 1);
  };

  const handleFeedBirds = async () => {
    if (cookieCount === 0) return; // Don't feed if no cookies
    
    setIsFeeding(true);
    try {
      const response = await fetch(import.meta.env.VITE_BACKEND_URL + '/api/feed', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${getCookie('stytch_session')}`,
        },
        body: JSON.stringify({ count: cookieCount }),
      });
      
      if (response.ok) {
        setCookieCount(0);
        console.log(`Fed ${cookieCount} cookies to birds!`);
      } else {
        console.error('Failed to feed birds');
      }
    } catch (error) {
      console.error('Error feeding birds:', error);
    } finally {
      setIsFeeding(false);
    }
  };

  const handleRequestPromotion = async () => {
    setIsRequestingPromotion(true);
    setPromotionResponse(null); // Clear previous response
    try {
      const response = await fetch(import.meta.env.VITE_BACKEND_URL + '/api/promote', {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${getCookie('stytch_session')}`,
        }
      });
      
      if (response.ok) {
        const result = await response.json();
        setPromotionResponse(result);
        if (!role?.includes(result.role)) {
          setTimeout(() => {
            window.location.reload();
          }, 1000);
        }
      } else {
        setPromotionResponse({ error: 'Failed to fetch promotion data' });
      }
    } catch (error) {
      console.error('Error requesting promotion:', error);
      setPromotionResponse({ error: 'Error fetching promotion data' });
    } finally {
      setIsRequestingPromotion(false);
    }
  };

  return (
    <div className="dashboard-container">
      <div className="dashboard-content">
      You are currently on team{' '}
        <strong>{organization?.organization_name}</strong> as a{' '}
        <strong>{role?.join(', ') || 'nobody'}</strong>.
        <br></br>
        <br></br>
        Bake some cookies for your teams!
        <br></br>
        <br></br>
        <div style={{ textAlign: 'center' }}>
          <span 
            onClick={handleCookieClick}
            style={{ 
              fontSize: '3rem', 
              cursor: 'pointer',
              userSelect: 'none',
              transition: 'transform 0.1s ease'
            }}
            onMouseDown={(e) => {
              e.currentTarget.style.transform = 'scale(0.95)';
            }}
            onMouseUp={(e) => {
              e.currentTarget.style.transform = 'scale(1)';
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.transform = 'scale(1)';
            }}
          >
            {organization?.organization_name.slice(-2)}
          </span>
          <br></br>
          <span style={{ fontSize: '1.2rem', fontWeight: 'bold' }}>
            Baked items: {cookieCount}
          </span>
          <br></br>
          <br></br>
          <div style={{ display: 'flex', gap: '15px', justifyContent: 'center', flexWrap: 'wrap' }}>
            {cookieCount > 0 && (
              <button
                onClick={handleFeedBirds}
                disabled={isFeeding}
                style={{
                  fontSize: '1rem',
                  padding: '12px 24px',
                  border: 'none',
                  borderRadius: '8px',
                  cursor: isFeeding ? 'not-allowed' : 'pointer',
                  backgroundColor: isFeeding ? '#cccccc' : '#4CAF50',
                  color: 'white',
                  fontWeight: 'bold',
                  transition: 'all 0.2s ease',
                  opacity: isFeeding ? 0.7 : 1,
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px'
                }}
                onMouseEnter={(e) => {
                  if (!isFeeding) {
                    e.currentTarget.style.backgroundColor = '#45a049';
                  }
                }}
                onMouseLeave={(e) => {
                  if (!isFeeding) {
                    e.currentTarget.style.backgroundColor = '#4CAF50';
                  }
                }}
              >
                🐦 {isFeeding ? 'Feeding Birds...' : `Feed ${cookieCount} to Birds`}
              </button>
            )}
            
            <button
              onClick={handleRequestPromotion}
              disabled={isRequestingPromotion}
              style={{
                fontSize: '1rem',
                padding: '12px 24px',
                border: 'none',
                borderRadius: '8px',
                cursor: isRequestingPromotion ? 'not-allowed' : 'pointer',
                backgroundColor: isRequestingPromotion ? '#cccccc' : '#2196F3',
                color: 'white',
                fontWeight: 'bold',
                transition: 'all 0.2s ease',
                opacity: isRequestingPromotion ? 0.7 : 1,
                display: 'flex',
                alignItems: 'center',
                gap: '8px'
              }}
              onMouseEnter={(e) => {
                if (!isRequestingPromotion) {
                  e.currentTarget.style.backgroundColor = '#1976D2';
                }
              }}
              onMouseLeave={(e) => {
                if (!isRequestingPromotion) {
                  e.currentTarget.style.backgroundColor = '#2196F3';
                }
              }}
            >
              ⬆️ {isRequestingPromotion ? 'Requesting...' : 'Request Promotion'}
            </button>
          </div>
          
          {promotionResponse && (
            <div>
              <h3 style={{ margin: '20px 0 0 0', color: '#333' }}>You are now a {promotionResponse.role || 'nobody'}</h3>
            </div>
          )}

        </div>
      </div>
    </div>
  );
};
