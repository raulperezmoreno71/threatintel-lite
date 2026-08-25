import Header from '../components/Header'
import Hero from '../components/Hero'
import AnalysisFeatures from '../components/AnalysisFeatures'
import HowItWorks from '../components/HowItWorks'
import FinalCTA from '../components/FinalCTA'
import Footer from '../components/Footer'

function LandingPage() {
    return (
    <>
        <Header />

        <main>
            <Hero />
            <AnalysisFeatures />
            <HowItWorks />
            <FinalCTA />
        </main>

      <Footer />
    </>
    )
}

export default LandingPage