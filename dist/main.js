/******/ (() => { // webpackBootstrap
// Basic interactivity for the website
document.addEventListener('DOMContentLoaded', () => {
    // Smooth scroll for anchor links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            document.querySelector(this.getAttribute('href')).scrollIntoView({
                behavior: 'smooth'
            });
        });
    });

    // Simple animation trigger for hero section
    const hero = document.querySelector('.hero');
    hero.classList.add('animate');

    // Console Easter egg
    console.log('QuantumSafe: Securing the future, one qubit at a time.');
});

/******/ })()
;