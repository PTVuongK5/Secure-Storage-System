import axios from 'axios'

const BASE = import.meta.env.VITE_FILE_SERVICE_URL || 'http://localhost:7003'

const instance = axios.create({ baseURL: BASE })

instance.interceptors.request.use((config)=>{
  const requestId = crypto.randomUUID()
  config.headers['X-Request-Id'] = requestId
  config.headers['X-Client-Time'] = new Date().toISOString()
  const st = sessionStorage.getItem('st')
  if(st){
   config.headers.Authorization =
      `Kerberos ${st}`
}
  return config
})

export default instance
