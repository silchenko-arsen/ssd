import axios  from 'axios'
import Cookies from "js-cookie";

const api =axios.create({
    baseURL: `${import.meta.env.VITE_APP_BASE_URL}/api`,
    headers: {
        'Content-Type': 'application/json',
    },
    withCredentials: true,
});

api.interceptors.request.use(config => {
        const token = Cookies.get('token');
        if(token) {
            config.headers.Authorization = `Bearer ${token}`
        }
        return config
    }, (error => Promise.reject(error))
)

api.interceptors.response.use(
    (response) => response,
    async (error) => {
        if (error.response?.status === 401) {
            Cookies.remove('token');
            window.location.href = '/login'; // Перенаправление на страницу входа
        }
        return Promise.reject(error);
    }
);



interface AuthRequest {
    email: string,
    password: string,
    username: string,
    code:string
}

interface AuthResponse {
    token: string,
    user: {
        id: number,
        email: string
    }
}



const auth = {
    login: async(credentials: AuthRequest): Promise<AuthResponse> => {
        const response = await api.post(`/auth/login`, credentials);
        Cookies.set('token', response.data, {secure: true, sameSite: "strict"}) //change secure: true
        console.log('Complete login ;d')
        return response.data
    },


    register: async (credentials: AuthRequest): Promise<AuthResponse> => {
        const response = await api.post<AuthResponse>(`/auth/register`, credentials)
        // Cookies.set('token', response.data, {secure: false, sameSite: "strict"})//change secure: true
        console.log(response.data)
        return response.data
    },

    verifi:async (credentials: AuthRequest): Promise<AuthResponse> => {
         const response = await api.post<AuthResponse>(`/auth/verify`, credentials)
        // @ts-ignore
        Cookies.set('token', response.data, {secure: true, sameSite: "strict"})//change secure: true
         console.log(response.data)
         return response.data
    },

    logout: () => {
        Cookies.remove('token')
    }
}

api.auth = auth




// const get = async<T>(url: string): Promise<T> => {
//     const response: AxiosResponse<T> = await api.get(url);
//     return response.data
// }
//
// const post = async <T, R>(url: string, data: T): Promise<R> => {
//   const response: AxiosResponse<R> = await api.post(url, data);
//   return response.data;
// };


// const projectsApi = {
//     getProjects: () => get<Project[]>('/projects'),
//     getProjectById: (id: number) => get<Project>(`/projects/${id}`),
//     createProject: (project: NewProject) => post<NewProject, Project>('/projects', project)
// }


// export const login = async(email: string, password: string) => {
//     return await axios.post(`${authUrl}/login`, {
//         email,
//         password
//     })
// }
//
// export const register = async(email: string, password: string) => {
//     return await axios.post(`${authUrl}/register`, {
//         email,
//         password
//     })
// }
//
// export const fetchData = async(url: string) => {
//     try {
//         const token = Cookies.get('token')
//         if(!token) {
//             console.log('Invalid token')
//             return null
//         }
//         const response = await axios.get(url, {
//             headers: {
//                 Authorization: `${token}`,
//                 "Content-Type": "application/json"
//             },
//         })
//         return response.data
//     } catch(e) {
//         console.error(`Error while fetching data`, e)
//     }
// }
//
// export const postData = async<T>(url: string, data: T | T[]) => {
//     try {
//         const token = Cookies.get('token')
//         if(!token) {
//             console.log('Invalid token')
//             return null;
//         }
//         const response = await axios.post(url, data, {
//             headers: {
//                 Authorization: `Bearer ${token}`,
//                 "Content-Type": "application/json"
//             }
//         })
//         return response.data
//     } catch(err) {
//         console.error('Error while posting data', err)
//         throw err;
//     }
// }

export default api
