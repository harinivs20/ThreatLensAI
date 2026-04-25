import axios from 'axios';

const api = axios.create({ baseURL: 'http://localhost:8000', timeout: 60000 });

export const scanInput    = (inputType, inputValue) =>
  api.post('/api/scan', { input_type: inputType, input_value: inputValue });
export const getHistory   = (limit = 20) => api.get(`/api/history?limit=${limit}`);
export const getStats     = () => api.get('/api/stats');
export const getCampaigns = () => api.get('/api/campaigns');
export const bulkScan     = (file) => {
  const form = new FormData();
  form.append('file', file);
  return api.post('/api/bulk-scan', form, { headers: { 'Content-Type': 'multipart/form-data' } });
};
export const getPdfUrl    = (scanId) => `http://localhost:8000/api/scan/${scanId}/pdf`;
export const getExportUrl = () => `http://localhost:8000/api/export/csv`;
export default api;
