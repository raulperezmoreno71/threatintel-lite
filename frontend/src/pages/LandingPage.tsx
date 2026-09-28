import Header from '../components/Header'
import Hero from '../components/Hero'
import AnalysisFeatures from '../components/AnalysisFeatures'
import HowItWorks from '../components/HowItWorks'
import UnderstandingResults from '../components/UnderstandingResults'
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
            <UnderstandingResults />
            <FinalCTA />
        </main>

      <Footer />
    </>
    )
}

export default LandingPage
