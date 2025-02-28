import React from 'react'
import NavBar from './Components/NavBar.jsx'
// import Dashboard from './Components/Dashboard'
import FileUpload from './Components/FileUpload'
import Displayimg from './Components/Displayimg'
import './Style.scss'


const Home = () => {
  return (
    <div className='home'>
        <NavBar />
        <div className="content">
             {/* <Dashboard /> */}
             <Displayimg /> 
            <FileUpload />
        </div>
        
    </div>
    
  )
}

export default Home