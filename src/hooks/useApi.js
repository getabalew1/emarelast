import { useState, useEffect } from 'react';
import { apiService } from '../services/api';
import toast from 'react-hot-toast';

export const useApi = (endpoint, dependencies = []) => {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchData = async () => {
      try {
        setLoading(true);
        setError(null);
        const result = await apiService.request(endpoint);
        setData(result);
      } catch (err) {
        setError(err.message);
        toast.error(`Failed to fetch data: ${err.message}`);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, dependencies);

  const refetch = async () => {
    try {
      setLoading(true);
      setError(null);
      const result = await apiService.request(endpoint);
      setData(result);
    } catch (err) {
      setError(err.message);
      toast.error(`Failed to fetch data: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  return { data, loading, error, refetch };
};

export const useApiMutation = () => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const mutate = async (endpoint, options = {}) => {
    try {
      setLoading(true);
      setError(null);
      const result = await apiService.request(endpoint, options);
      return result;
    } catch (err) {
      setError(err.message);
      throw err;
    } finally {
      setLoading(false);
    }
  };

  return { mutate, loading, error };
};